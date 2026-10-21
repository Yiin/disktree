//! A scanned tree as bytes.
//!
//! Nodes go in pre-order, each followed by its children, so the far side
//! rebuilds the tree with one stack and no recursion however deep it is.
//! A whole disk is millions of nodes, so each is a few bytes before zstd:
//!
//! * a flags byte and a class byte (category and reclaim reason),
//! * the name,
//! * `bytes`, in 512-byte sectors when it is a whole number of them,
//!   which every block-measured size is,
//! * `files` and `dirs` only when they are not what a leaf has,
//! * `modified` as the distance below the parent's, which is the newest
//!   time beneath it,
//! * the identity and the child count only when there are any.
//!
//! The encoder cuts the stream into chunks at node boundaries, so each
//! chunk is compressed and decoded on its own while the rest is still on
//! the wire.

use std::io;
use std::num::NonZeroU64;

use disktree_core::classify::{Category, Reclaim};
use disktree_core::tree::{Node, NodeKind};

use crate::wire::{Decoder, Encoder, invalid};

const KIND: u8 = 0b11;
const READ_ERROR: u8 = 1 << 2;
const IDENTITY: u8 = 1 << 3;
const COUNTS: u8 = 1 << 4;
const CHILDREN: u8 = 1 << 5;
const SECTORS: u8 = 1 << 6;

/// Raw bytes per chunk before compression. Large enough that zstd finds
/// the repeats in names, small enough that the first chunk is on its way
/// while the encoder is still walking.
pub const CHUNK: usize = 1 << 20;

/// Encode `root`, handing each finished chunk to `emit`. Returns the
/// number of nodes.
pub fn encode_tree(
    root: &Node,
    chunk: usize,
    mut emit: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<u64> {
    let mut out = Encoder::new();
    let mut nodes = 1;
    encode_node(&mut out, root, 0);
    // Each frame is a parent's remaining children and its `modified`.
    let mut stack = vec![(root.children.iter(), root.modified)];
    while let Some((children, parent_modified)) = stack.last_mut() {
        let Some(node) = children.next() else {
            stack.pop();
            continue;
        };
        encode_node(&mut out, node, *parent_modified);
        nodes += 1;
        if !node.children.is_empty() {
            stack.push((node.children.iter(), node.modified));
        }
        if out.buf.len() >= chunk {
            emit(&out.buf)?;
            out.buf.clear();
        }
    }
    if !out.buf.is_empty() {
        emit(&out.buf)?;
    }
    Ok(nodes)
}

fn encode_node(out: &mut Encoder, node: &Node, parent_modified: i64) {
    let leaf_counts =
        node.files == u64::from(node.kind == NodeKind::File) && node.dirs == 0;
    let sectors = node.bytes.is_multiple_of(512);
    let mut flags = kind_code(node.kind);
    for (set, flag) in [
        (node.read_error, READ_ERROR),
        (node.inode.is_some(), IDENTITY),
        (!leaf_counts, COUNTS),
        (!node.children.is_empty(), CHILDREN),
        (sectors, SECTORS),
    ] {
        if set {
            flags |= flag;
        }
    }
    out.u8(flags);
    out.u8(category_code(node.category) | reclaim_code(node.reclaim) << 4);
    out.str(&node.name);
    out.uint(if sectors {
        node.bytes / 512
    } else {
        node.bytes
    });
    if !leaf_counts {
        out.uint(node.files);
        out.uint(u64::from(node.dirs));
    }
    out.int(parent_modified.wrapping_sub(node.modified));
    if let Some((device, inode)) = node.inode {
        out.uint(device);
        out.uint(inode.get());
    }
    if !node.children.is_empty() {
        out.usize(node.children.len());
    }
}

/// Rebuilds a tree from the chunks [`encode_tree`] produced, in order.
#[derive(Debug, Default)]
pub struct TreeBuilder {
    /// Directories whose children are still arriving, outermost first,
    /// with how many are still to come.
    open: Vec<(Node, usize)>,
    root: Option<Node>,
    nodes: u64,
}

impl TreeBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Nodes decoded so far.
    pub const fn nodes(&self) -> u64 {
        self.nodes
    }

    /// Decode every node in `chunk`.
    pub fn feed(&mut self, chunk: &[u8]) -> io::Result<()> {
        let mut input = Decoder::new(chunk);
        while !input.is_empty() {
            if self.root.is_some() {
                return Err(invalid("nodes after the root was complete"));
            }
            let parent_modified =
                self.open.last().map_or(0, |(parent, _)| parent.modified);
            let (node, children) = decode_node(&mut input, parent_modified)?;
            self.nodes += 1;
            if children > 0 {
                self.open.push((node, children));
            } else {
                self.attach(node);
            }
        }
        Ok(())
    }

    /// Hand `node` to the directory it belongs in, closing every
    /// directory it completes.
    fn attach(&mut self, mut node: Node) {
        loop {
            let Some((parent, remaining)) = self.open.last_mut() else {
                self.root = Some(node);
                return;
            };
            parent.children.push(node);
            *remaining -= 1;
            if *remaining > 0 {
                return;
            }
            let Some((done, _)) = self.open.pop() else {
                return;
            };
            node = done;
        }
    }

    /// The tree, once every chunk has been fed.
    pub fn finish(self) -> io::Result<Node> {
        self.root
            .ok_or_else(|| invalid("the tree ended before its last node"))
    }
}

fn decode_node(
    input: &mut Decoder<'_>,
    parent_modified: i64,
) -> io::Result<(Node, usize)> {
    let flags = input.u8()?;
    let class = input.u8()?;
    let kind = kind_of(flags & KIND);
    let name: Box<str> = input.str()?.into();
    let raw = input.uint()?;
    let bytes = if flags & SECTORS == 0 {
        raw
    } else {
        raw.checked_mul(512)
            .ok_or_else(|| invalid("a size past 64 bits"))?
    };
    let mut node = Node::entry(name, kind, bytes);
    if flags & COUNTS != 0 {
        node.files = input.uint()?;
        node.dirs = input.u32()?;
    }
    node.modified = parent_modified.wrapping_sub(input.int()?);
    if flags & IDENTITY != 0 {
        let device = input.uint()?;
        let inode = NonZeroU64::new(input.uint()?)
            .ok_or_else(|| invalid("an identity with inode zero"))?;
        node.inode = Some((device, inode));
    }
    node.read_error = flags & READ_ERROR != 0;
    node.category = category_of(class & 0x0F)?;
    node.reclaim = reclaim_of(class >> 4)?;
    let children = if flags & CHILDREN == 0 {
        0
    } else {
        let count = input.usize()?;
        if count == 0 {
            return Err(invalid("a child count of zero behind its flag"));
        }
        // Capped: the count is not proven until the children arrive.
        node.children.reserve(count.min(1 << 16));
        count
    };
    Ok((node, children))
}

const fn kind_code(kind: NodeKind) -> u8 {
    match kind {
        NodeKind::Directory => 0,
        NodeKind::File => 1,
        NodeKind::Symlink => 2,
        NodeKind::Other => 3,
    }
}

const fn kind_of(code: u8) -> NodeKind {
    match code {
        0 => NodeKind::Directory,
        1 => NodeKind::File,
        2 => NodeKind::Symlink,
        _ => NodeKind::Other,
    }
}

/// Spelled out both ways rather than cast, so reordering the enum in core
/// cannot silently change what a number means on the wire.
const fn category_code(category: Category) -> u8 {
    match category {
        Category::Other => 0,
        Category::Code => 1,
        Category::AgentScratch => 2,
        Category::Toolchain => 3,
        Category::Synced => 4,
        Category::Git => 5,
        Category::Media => 6,
        Category::Documents => 7,
        Category::Cache => 8,
    }
}

fn category_of(code: u8) -> io::Result<Category> {
    Ok(match code {
        0 => Category::Other,
        1 => Category::Code,
        2 => Category::AgentScratch,
        3 => Category::Toolchain,
        4 => Category::Synced,
        5 => Category::Git,
        6 => Category::Media,
        7 => Category::Documents,
        8 => Category::Cache,
        other => return Err(invalid(format!("category {other}"))),
    })
}

const fn reclaim_code(reclaim: Option<Reclaim>) -> u8 {
    match reclaim {
        None => 0,
        Some(Reclaim::Regenerable) => 1,
        Some(Reclaim::SyncHistory) => 2,
        Some(Reclaim::PackageStore) => 3,
        Some(Reclaim::BuildOutput) => 4,
        Some(Reclaim::Reinstallable) => 5,
        Some(Reclaim::SandboxLayers) => 6,
        Some(Reclaim::Snapshots) => 7,
        Some(Reclaim::Trash) => 8,
        Some(Reclaim::Temporary) => 9,
    }
}

fn reclaim_of(code: u8) -> io::Result<Option<Reclaim>> {
    Ok(Some(match code {
        0 => return Ok(None),
        1 => Reclaim::Regenerable,
        2 => Reclaim::SyncHistory,
        3 => Reclaim::PackageStore,
        4 => Reclaim::BuildOutput,
        5 => Reclaim::Reinstallable,
        6 => Reclaim::SandboxLayers,
        7 => Reclaim::Snapshots,
        8 => Reclaim::Trash,
        9 => Reclaim::Temporary,
        other => return Err(invalid(format!("reclaim reason {other}"))),
    }))
}

/// Every field of two trees, node by node: what a round trip must keep.
/// Shared with the loopback tests, which compare an agent's tree with a
/// local scan.
pub fn same_tree(left: &Node, right: &Node) -> Result<(), String> {
    let mut stack = vec![(left, right, String::new())];
    while let Some((left, right, path)) = stack.pop() {
        let path = format!("{path}/{}", left.name);
        let fields = [
            ("name", left.name == right.name),
            ("kind", left.kind == right.kind),
            ("bytes", left.bytes == right.bytes),
            ("files", left.files == right.files),
            ("dirs", left.dirs == right.dirs),
            ("inode", left.inode == right.inode),
            ("read_error", left.read_error == right.read_error),
            ("modified", left.modified == right.modified),
            ("category", left.category == right.category),
            ("reclaim", left.reclaim == right.reclaim),
            ("children", left.children.len() == right.children.len()),
        ];
        if let Some((field, _)) = fields.iter().find(|(_, same)| !same) {
            return Err(format!("{path}: {field} differs"));
        }
        for (left, right) in left.children.iter().zip(&right.children) {
            stack.push((left, right, path.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(root: &Node, chunk: usize) -> (Node, usize) {
        let mut chunks = Vec::new();
        let nodes = encode_tree(root, chunk, |bytes| {
            chunks.push(bytes.to_vec());
            Ok(())
        })
        .unwrap();
        let mut builder = TreeBuilder::new();
        for bytes in &chunks {
            builder.feed(bytes).unwrap();
        }
        assert_eq!(builder.nodes(), nodes);
        (builder.finish().unwrap(), chunks.len())
    }

    /// Every field set to something a default would not be.
    fn odd_tree() -> Node {
        let mut root = Node::directory("root");
        root.modified = 1_700_000_000;
        root.bytes = 4096 * 3 + 7;
        root.files = 3;
        root.dirs = 2;
        root.category = Category::Code;
        let mut sub = Node::directory("line\nbreak \u{e9}\u{1F600}");
        sub.read_error = true;
        sub.reclaim = Some(Reclaim::Temporary);
        sub.category = Category::Cache;
        sub.modified = 1_600_000_000;
        let mut linked = Node::entry("linked", NodeKind::File, 4096);
        linked.inode = Some((66306, NonZeroU64::new(u64::MAX).unwrap()));
        linked.modified = -5;
        sub.children.push(linked);
        sub.children.push(Node::entry("", NodeKind::Symlink, 0));
        root.children.push(sub);
        root.children
            .push(Node::entry("odd size", NodeKind::File, 7));
        root.children.push(Node::entry("fifo", NodeKind::Other, 0));
        let mut empty = Node::directory("empty");
        empty.modified = i64::MAX;
        root.children.push(empty);
        root
    }

    #[test]
    fn every_field_survives_a_round_trip() {
        let root = odd_tree();
        let (back, _) = round_trip(&root, CHUNK);
        same_tree(&root, &back).unwrap();
    }

    #[test]
    fn chunks_split_anywhere_between_nodes() {
        let root = odd_tree();
        let (back, chunks) = round_trip(&root, 1);
        assert!(chunks > 1, "one node per chunk");
        same_tree(&root, &back).unwrap();
    }

    #[test]
    fn a_wide_and_deep_tree_round_trips_without_recursion() {
        let mut root = Node::directory("wide");
        for index in 0..200_000_u64 {
            let mut file =
                Node::entry(format!("f{index}"), NodeKind::File, index * 512);
            file.modified = index.cast_signed();
            root.children.push(file);
        }
        let mut deep = Node::directory("deep-0");
        for level in 1..20_000 {
            let mut parent = Node::directory(format!("deep-{level}"));
            parent.children.push(deep);
            deep = parent;
        }
        root.children.push(deep);
        let (back, chunks) = round_trip(&root, CHUNK);
        assert!(chunks > 1);
        same_tree(&root, &back).unwrap();
        // Dropping 20 000 levels recursively is the test's problem, not the
        // codec's; unwind it by hand.
        for tree in [root, back] {
            let mut pending = vec![tree];
            while let Some(mut node) = pending.pop() {
                pending.append(&mut node.children);
            }
        }
    }

    #[test]
    fn a_truncated_tree_is_an_error() {
        let mut chunks = Vec::new();
        encode_tree(&odd_tree(), 1, |bytes| {
            chunks.push(bytes.to_vec());
            Ok(())
        })
        .unwrap();
        let mut builder = TreeBuilder::new();
        for bytes in &chunks[..chunks.len() - 1] {
            builder.feed(bytes).unwrap();
        }
        assert!(builder.finish().is_err());
    }
}
