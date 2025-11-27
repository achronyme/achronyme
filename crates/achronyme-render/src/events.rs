//! Event System for AUI
//!
//! This module provides:
//! - Hit testing (finding which node is under the cursor)
//! - Event types (Click, Hover, etc.)
//! - Event propagation (bubbling up the tree)
//! - Callback registration

use crate::node::{NodeId, UiTree};
use std::collections::HashMap;

/// Mouse button
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

/// Event types that can be handled
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventType {
    /// Mouse entered the node
    MouseEnter,
    /// Mouse left the node
    MouseLeave,
    /// Mouse is over the node (fired continuously)
    MouseMove,
    /// Mouse button pressed down on the node
    MouseDown(MouseButton),
    /// Mouse button released on the node
    MouseUp(MouseButton),
    /// Full click (down + up on same node)
    Click(MouseButton),
}

/// Event data passed to handlers
#[derive(Debug, Clone)]
pub struct Event {
    /// Type of event
    pub event_type: EventType,
    /// Target node that received the event
    pub target: NodeId,
    /// Mouse position relative to window
    pub x: f32,
    pub y: f32,
    /// Mouse position relative to the target node
    pub local_x: f32,
    pub local_y: f32,
    /// Whether propagation should stop
    pub propagation_stopped: bool,
}

impl Event {
    /// Stop event from bubbling to parent nodes
    pub fn stop_propagation(&mut self) {
        self.propagation_stopped = true;
    }
}

/// Callback function type
pub type EventCallback = Box<dyn Fn(&Event) + Send + Sync>;

/// Manages event handlers for nodes
pub struct EventManager {
    /// Handlers registered per node per event type
    handlers: HashMap<NodeId, HashMap<EventType, Vec<EventCallback>>>,
    /// Currently hovered node
    hovered: Option<NodeId>,
    /// Node where mouse button was pressed (for click detection)
    mouse_down_target: Option<NodeId>,
    /// Current mouse position
    mouse_x: f32,
    mouse_y: f32,
}

impl EventManager {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            hovered: None,
            mouse_down_target: None,
            mouse_x: 0.0,
            mouse_y: 0.0,
        }
    }

    /// Register an event handler for a node
    pub fn on(&mut self, node: NodeId, event_type: EventType, callback: EventCallback) {
        self.handlers
            .entry(node)
            .or_default()
            .entry(event_type)
            .or_default()
            .push(callback);
    }

    /// Register a click handler (convenience method)
    pub fn on_click(&mut self, node: NodeId, callback: impl Fn(&Event) + Send + Sync + 'static) {
        self.on(
            node,
            EventType::Click(MouseButton::Left),
            Box::new(callback),
        );
    }

    /// Register a hover enter handler
    pub fn on_hover_enter(
        &mut self,
        node: NodeId,
        callback: impl Fn(&Event) + Send + Sync + 'static,
    ) {
        self.on(node, EventType::MouseEnter, Box::new(callback));
    }

    /// Register a hover leave handler
    pub fn on_hover_leave(
        &mut self,
        node: NodeId,
        callback: impl Fn(&Event) + Send + Sync + 'static,
    ) {
        self.on(node, EventType::MouseLeave, Box::new(callback));
    }

    /// Remove all handlers for a node
    pub fn remove_handlers(&mut self, node: NodeId) {
        self.handlers.remove(&node);
    }

    /// Get the currently hovered node
    pub fn hovered(&self) -> Option<NodeId> {
        self.hovered
    }

    /// Process mouse movement
    pub fn handle_mouse_move(&mut self, tree: &UiTree, root: NodeId, x: f32, y: f32) -> Vec<Event> {
        self.mouse_x = x;
        self.mouse_y = y;

        let mut events = Vec::new();
        let hit = hit_test(tree, root, x, y);

        // Handle hover changes
        if hit != self.hovered {
            // Mouse leave old node
            if let Some(old) = self.hovered {
                let (local_x, local_y) = self.local_coords(tree, old, x, y);
                events.push(Event {
                    event_type: EventType::MouseLeave,
                    target: old,
                    x,
                    y,
                    local_x,
                    local_y,
                    propagation_stopped: false,
                });
            }

            // Mouse enter new node
            if let Some(new) = hit {
                let (local_x, local_y) = self.local_coords(tree, new, x, y);
                events.push(Event {
                    event_type: EventType::MouseEnter,
                    target: new,
                    x,
                    y,
                    local_x,
                    local_y,
                    propagation_stopped: false,
                });
            }

            self.hovered = hit;
        }

        // Always fire MouseMove on current hover target
        if let Some(target) = hit {
            let (local_x, local_y) = self.local_coords(tree, target, x, y);
            events.push(Event {
                event_type: EventType::MouseMove,
                target,
                x,
                y,
                local_x,
                local_y,
                propagation_stopped: false,
            });
        }

        events
    }

    /// Process mouse button press
    pub fn handle_mouse_down(&mut self, tree: &UiTree, button: MouseButton) -> Option<Event> {
        let target = self.hovered?;
        self.mouse_down_target = Some(target);

        let (local_x, local_y) = self.local_coords(tree, target, self.mouse_x, self.mouse_y);
        Some(Event {
            event_type: EventType::MouseDown(button),
            target,
            x: self.mouse_x,
            y: self.mouse_y,
            local_x,
            local_y,
            propagation_stopped: false,
        })
    }

    /// Process mouse button press at specific coordinates (for deferred/queued events)
    pub fn handle_mouse_down_at(
        &mut self,
        tree: &UiTree,
        root: NodeId,
        x: f32,
        y: f32,
        button: MouseButton,
    ) -> Option<Event> {
        // Do hit test at the specified coordinates
        let target = hit_test(tree, root, x, y)?;
        self.mouse_down_target = Some(target);

        let (local_x, local_y) = self.local_coords(tree, target, x, y);
        Some(Event {
            event_type: EventType::MouseDown(button),
            target,
            x,
            y,
            local_x,
            local_y,
            propagation_stopped: false,
        })
    }

    /// Process mouse button release
    pub fn handle_mouse_up(&mut self, tree: &UiTree, button: MouseButton) -> Vec<Event> {
        let mut events = Vec::new();

        if let Some(target) = self.hovered {
            let (local_x, local_y) = self.local_coords(tree, target, self.mouse_x, self.mouse_y);

            // MouseUp event
            events.push(Event {
                event_type: EventType::MouseUp(button),
                target,
                x: self.mouse_x,
                y: self.mouse_y,
                local_x,
                local_y,
                propagation_stopped: false,
            });

            // Click event (if mouse down and up on same node)
            if self.mouse_down_target == Some(target) {
                events.push(Event {
                    event_type: EventType::Click(button),
                    target,
                    x: self.mouse_x,
                    y: self.mouse_y,
                    local_x,
                    local_y,
                    propagation_stopped: false,
                });
            }
        }

        self.mouse_down_target = None;
        events
    }

    /// Dispatch an event, calling handlers and bubbling up the tree
    pub fn dispatch(&self, tree: &UiTree, event: &mut Event) {
        let mut current = Some(event.target);

        while let Some(node_id) = current {
            if event.propagation_stopped {
                break;
            }

            // Call handlers for this node
            if let Some(node_handlers) = self.handlers.get(&node_id) {
                if let Some(type_handlers) = node_handlers.get(&event.event_type) {
                    for handler in type_handlers {
                        handler(event);
                        if event.propagation_stopped {
                            break;
                        }
                    }
                }
            }

            // Bubble to parent
            current = tree.get(node_id).and_then(|n| n.parent);
        }
    }

    /// Calculate local coordinates for a node
    fn local_coords(&self, tree: &UiTree, node: NodeId, x: f32, y: f32) -> (f32, f32) {
        if let Some(n) = tree.get(node) {
            (x - n.layout.x, y - n.layout.y)
        } else {
            (x, y)
        }
    }
}

impl Default for EventManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Hit test: find the deepest node at coordinates (x, y)
/// Returns None if no node is hit
pub fn hit_test(tree: &UiTree, root: NodeId, x: f32, y: f32) -> Option<NodeId> {
    hit_test_recursive(tree, root, x, y)
}

fn hit_test_recursive(tree: &UiTree, node_id: NodeId, x: f32, y: f32) -> Option<NodeId> {
    let node = tree.get(node_id)?;
    let layout = &node.layout;

    // Check if point is within this node's bounds
    if x < layout.x || x > layout.x + layout.width || y < layout.y || y > layout.y + layout.height {
        return None;
    }

    // Check children in reverse order (last child is on top)
    for &child_id in node.children.iter().rev() {
        if let Some(hit) = hit_test_recursive(tree, child_id, x, y) {
            return Some(hit);
        }
    }

    // No child hit, return this node
    Some(node_id)
}

/// Interactive state for a node (for styling)
#[derive(Debug, Clone, Copy, Default)]
pub struct InteractiveState {
    /// Mouse is over this node
    pub hovered: bool,
    /// Mouse button is pressed on this node
    pub pressed: bool,
    /// Node has keyboard focus
    pub focused: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::UiNode;

    #[test]
    fn test_hit_test_simple() {
        let mut tree = UiTree::new();

        // Create a simple tree:
        // root (0,0 - 400x300)
        //   └── child (50,50 - 100x100)
        let root = tree.insert(UiNode::container());
        tree.set_root(root);
        if let Some(node) = tree.get_mut(root) {
            node.layout.x = 0.0;
            node.layout.y = 0.0;
            node.layout.width = 400.0;
            node.layout.height = 300.0;
        }

        let child = tree.insert(UiNode::container());
        tree.add_child(root, child);
        if let Some(node) = tree.get_mut(child) {
            node.layout.x = 50.0;
            node.layout.y = 50.0;
            node.layout.width = 100.0;
            node.layout.height = 100.0;
        }

        // Hit child
        assert_eq!(hit_test(&tree, root, 75.0, 75.0), Some(child));

        // Hit root (outside child)
        assert_eq!(hit_test(&tree, root, 10.0, 10.0), Some(root));

        // Miss everything
        assert_eq!(hit_test(&tree, root, 500.0, 500.0), None);
    }

    #[test]
    fn test_hit_test_nested() {
        let mut tree = UiTree::new();

        // root -> child -> grandchild
        let root = tree.insert(UiNode::container());
        tree.set_root(root);
        if let Some(node) = tree.get_mut(root) {
            node.layout.x = 0.0;
            node.layout.y = 0.0;
            node.layout.width = 400.0;
            node.layout.height = 300.0;
        }

        let child = tree.insert(UiNode::container());
        tree.add_child(root, child);
        if let Some(node) = tree.get_mut(child) {
            node.layout.x = 50.0;
            node.layout.y = 50.0;
            node.layout.width = 200.0;
            node.layout.height = 200.0;
        }

        let grandchild = tree.insert(UiNode::button(1, "Click"));
        tree.add_child(child, grandchild);
        if let Some(node) = tree.get_mut(grandchild) {
            node.layout.x = 75.0;
            node.layout.y = 75.0;
            node.layout.width = 100.0;
            node.layout.height = 50.0;
        }

        // Hit grandchild
        assert_eq!(hit_test(&tree, root, 100.0, 90.0), Some(grandchild));

        // Hit child (outside grandchild)
        assert_eq!(hit_test(&tree, root, 60.0, 60.0), Some(child));
    }

    #[test]
    fn test_event_manager_hover() {
        let mut tree = UiTree::new();
        let mut events = EventManager::new();

        let root = tree.insert(UiNode::container());
        tree.set_root(root);
        if let Some(node) = tree.get_mut(root) {
            node.layout.x = 0.0;
            node.layout.y = 0.0;
            node.layout.width = 400.0;
            node.layout.height = 300.0;
        }

        // Move mouse into root
        let evts = events.handle_mouse_move(&tree, root, 100.0, 100.0);
        assert!(evts.iter().any(|e| e.event_type == EventType::MouseEnter));
        assert_eq!(events.hovered(), Some(root));

        // Move mouse out
        let evts = events.handle_mouse_move(&tree, root, 500.0, 500.0);
        assert!(evts.iter().any(|e| e.event_type == EventType::MouseLeave));
        assert_eq!(events.hovered(), None);
    }
}
