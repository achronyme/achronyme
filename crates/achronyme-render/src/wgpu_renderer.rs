//! GPU-accelerated renderer using wgpu
//!
//! This module provides high-performance 2D rendering for the AUI engine.
//! It uses wgpu for cross-platform GPU acceleration (Vulkan, Metal, DX12, WebGPU).

use crate::node::{NodeContent, NodeId, NodeStyle, PlotSeries, UiTree};
use crate::text::{FontWeight, TextAlign, TextRenderer};
use bytemuck::{Pod, Zeroable};
use std::sync::Arc;
use wgpu::util::DeviceExt;
use winit::window::Window;

/// Color as ARGB u32 (0xAARRGGBB)
pub type Color = u32;

/// Convert ARGB color to RGBA f32 array for GPU
fn color_to_rgba(color: Color) -> [f32; 4] {
    let a = ((color >> 24) & 0xFF) as f32 / 255.0;
    let r = ((color >> 16) & 0xFF) as f32 / 255.0;
    let g = ((color >> 8) & 0xFF) as f32 / 255.0;
    let b = (color & 0xFF) as f32 / 255.0;
    [r, g, b, a]
}

/// Vertex data for rectangle rendering
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
pub struct RectVertex {
    pub position: [f32; 2],
    pub uv: [f32; 2],
    pub color: [f32; 4],
    pub rect_pos: [f32; 2],
    pub rect_size: [f32; 2],
    pub border_radius: f32,
    pub border_width: f32,
    pub border_color: [f32; 4],
}

impl RectVertex {
    const ATTRIBS: [wgpu::VertexAttribute; 8] = wgpu::vertex_attr_array![
        0 => Float32x2,
        1 => Float32x2,
        2 => Float32x4,
        3 => Float32x2,
        4 => Float32x2,
        5 => Float32,
        6 => Float32,
        7 => Float32x4,
    ];

    fn desc() -> wgpu::VertexBufferLayout<'static> {
        wgpu::VertexBufferLayout {
            array_stride: std::mem::size_of::<RectVertex>() as wgpu::BufferAddress,
            step_mode: wgpu::VertexStepMode::Vertex,
            attributes: &Self::ATTRIBS,
        }
    }
}

/// Vertex data for text rendering
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
pub struct TextVertex {
    pub position: [f32; 2],
    pub uv: [f32; 2],
    pub color: [f32; 4],
}

impl TextVertex {
    const ATTRIBS: [wgpu::VertexAttribute; 3] = wgpu::vertex_attr_array![
        0 => Float32x2,
        1 => Float32x2,
        2 => Float32x4,
    ];

    fn desc() -> wgpu::VertexBufferLayout<'static> {
        wgpu::VertexBufferLayout {
            array_stride: std::mem::size_of::<TextVertex>() as wgpu::BufferAddress,
            step_mode: wgpu::VertexStepMode::Vertex,
            attributes: &Self::ATTRIBS,
        }
    }
}

/// Vertex data for line rendering
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
pub struct LineVertex {
    pub position: [f32; 2],      // Vertex position
    pub line_start: [f32; 2],    // Line segment start
    pub line_end: [f32; 2],      // Line segment end
    pub color: [f32; 4],         // Line color
    pub thickness: f32,          // Line thickness
    pub _padding: f32,           // Padding for alignment
}

impl LineVertex {
    const ATTRIBS: [wgpu::VertexAttribute; 5] = wgpu::vertex_attr_array![
        0 => Float32x2,  // position
        1 => Float32x2,  // line_start
        2 => Float32x2,  // line_end
        3 => Float32x4,  // color
        4 => Float32,    // thickness
    ];

    fn desc() -> wgpu::VertexBufferLayout<'static> {
        wgpu::VertexBufferLayout {
            array_stride: std::mem::size_of::<LineVertex>() as wgpu::BufferAddress,
            step_mode: wgpu::VertexStepMode::Vertex,
            attributes: &Self::ATTRIBS,
        }
    }
}

/// A text item to be rendered
struct TextItem {
    text: String,
    x: f32,
    y: f32,
    width: f32,
    height: f32,
    font_size: f32,
    color: Color,
    align: TextAlign,
    weight: FontWeight,
}

/// Uniforms passed to shaders
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
struct Uniforms {
    screen_size: [f32; 2],
    _padding: [f32; 2],
}

/// Interactive state passed to renderer
#[derive(Default, Clone, Copy)]
pub struct RenderState {
    pub hovered: Option<NodeId>,
    pub pressed: Option<NodeId>,
    pub focused: Option<NodeId>,
}

/// GPU-accelerated renderer
pub struct WgpuRenderer {
    surface: wgpu::Surface<'static>,
    device: wgpu::Device,
    queue: wgpu::Queue,
    config: wgpu::SurfaceConfiguration,
    size: (u32, u32),

    // Rectangle pipeline
    rect_pipeline: wgpu::RenderPipeline,
    rect_vertices: Vec<RectVertex>,
    rect_vertex_buffer: wgpu::Buffer,
    rect_index_buffer: wgpu::Buffer,
    max_rects: usize,

    // Line pipeline
    line_pipeline: wgpu::RenderPipeline,
    line_vertices: Vec<LineVertex>,
    line_vertex_buffer: wgpu::Buffer,
    line_index_buffer: wgpu::Buffer,
    max_lines: usize,

    // Text pipeline
    text_pipeline: wgpu::RenderPipeline,
    text_renderer: TextRenderer,
    text_items: Vec<TextItem>,
    text_texture: wgpu::Texture,
    text_texture_view: wgpu::TextureView,
    text_bind_group: wgpu::BindGroup,
    text_vertex_buffer: wgpu::Buffer,
    text_index_buffer: wgpu::Buffer,
    max_text_quads: usize,

    // Shared resources
    uniform_buffer: wgpu::Buffer,
    uniform_bind_group: wgpu::BindGroup,

    // Staging buffer for text (CPU-side)
    text_staging_buffer: Vec<u8>,

    clear_color: wgpu::Color,
}

impl WgpuRenderer {
    /// Create a new GPU renderer for the given window
    pub fn new(window: Arc<Window>) -> Self {
        let size = window.inner_size();
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
            backends: wgpu::Backends::all(),
            ..Default::default()
        });

        let surface = instance.create_surface(window).unwrap();

        let (adapter, device, queue) = pollster::block_on(async {
            let adapter = instance
                .request_adapter(&wgpu::RequestAdapterOptions {
                    power_preference: wgpu::PowerPreference::HighPerformance,
                    compatible_surface: Some(&surface),
                    force_fallback_adapter: false,
                })
                .await
                .expect("Failed to find GPU adapter");

            let (device, queue) = adapter
                .request_device(
                    &wgpu::DeviceDescriptor {
                        label: Some("AUI Device"),
                        required_features: wgpu::Features::empty(),
                        required_limits: wgpu::Limits::default(),
                        memory_hints: wgpu::MemoryHints::Performance,
                    },
                    None,
                )
                .await
                .expect("Failed to create device");

            (adapter, device, queue)
        });

        let surface_caps = surface.get_capabilities(&adapter);
        let surface_format = surface_caps
            .formats
            .iter()
            .find(|f| f.is_srgb())
            .copied()
            .unwrap_or(surface_caps.formats[0]);

        let config = wgpu::SurfaceConfiguration {
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT,
            format: surface_format,
            width: size.width.max(1),
            height: size.height.max(1),
            present_mode: wgpu::PresentMode::AutoVsync,
            alpha_mode: surface_caps.alpha_modes[0],
            view_formats: vec![],
            desired_maximum_frame_latency: 2,
        };
        surface.configure(&device, &config);

        // Uniform buffer
        let uniforms = Uniforms {
            screen_size: [size.width as f32, size.height as f32],
            _padding: [0.0, 0.0],
        };
        let uniform_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("Uniform Buffer"),
            contents: bytemuck::cast_slice(&[uniforms]),
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
        });

        let uniform_bind_group_layout =
            device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
                label: Some("Uniform Bind Group Layout"),
                entries: &[wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::VERTEX | wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Uniform,
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                }],
            });

        let uniform_bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("Uniform Bind Group"),
            layout: &uniform_bind_group_layout,
            entries: &[wgpu::BindGroupEntry {
                binding: 0,
                resource: uniform_buffer.as_entire_binding(),
            }],
        });

        // ===== Rectangle Pipeline =====
        let rect_shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("Rect Shader"),
            source: wgpu::ShaderSource::Wgsl(include_str!("shaders/rect.wgsl").into()),
        });

        let rect_pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("Rect Pipeline Layout"),
            bind_group_layouts: &[&uniform_bind_group_layout],
            push_constant_ranges: &[],
        });

        let rect_pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("Rect Pipeline"),
            layout: Some(&rect_pipeline_layout),
            vertex: wgpu::VertexState {
                module: &rect_shader,
                entry_point: Some("vs_main"),
                buffers: &[RectVertex::desc()],
                compilation_options: Default::default(),
            },
            fragment: Some(wgpu::FragmentState {
                module: &rect_shader,
                entry_point: Some("fs_main"),
                targets: &[Some(wgpu::ColorTargetState {
                    format: config.format,
                    blend: Some(wgpu::BlendState::ALPHA_BLENDING),
                    write_mask: wgpu::ColorWrites::ALL,
                })],
                compilation_options: Default::default(),
            }),
            primitive: wgpu::PrimitiveState {
                topology: wgpu::PrimitiveTopology::TriangleList,
                cull_mode: None,
                ..Default::default()
            },
            depth_stencil: None,
            multisample: wgpu::MultisampleState::default(),
            multiview: None,
            cache: None,
        });

        let max_rects = 10000;
        let rect_vertex_buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("Rect Vertex Buffer"),
            size: (max_rects * 4 * std::mem::size_of::<RectVertex>()) as u64,
            usage: wgpu::BufferUsages::VERTEX | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let rect_indices: Vec<u32> = (0..max_rects as u32)
            .flat_map(|i| {
                let base = i * 4;
                [base, base + 1, base + 2, base, base + 2, base + 3]
            })
            .collect();
        let rect_index_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("Rect Index Buffer"),
            contents: bytemuck::cast_slice(&rect_indices),
            usage: wgpu::BufferUsages::INDEX,
        });

        // ===== Line Pipeline =====
        let line_shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("Line Shader"),
            source: wgpu::ShaderSource::Wgsl(include_str!("shaders/line.wgsl").into()),
        });

        let line_pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("Line Pipeline Layout"),
            bind_group_layouts: &[&uniform_bind_group_layout],
            push_constant_ranges: &[],
        });

        let line_pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("Line Pipeline"),
            layout: Some(&line_pipeline_layout),
            vertex: wgpu::VertexState {
                module: &line_shader,
                entry_point: Some("vs_main"),
                buffers: &[LineVertex::desc()],
                compilation_options: Default::default(),
            },
            fragment: Some(wgpu::FragmentState {
                module: &line_shader,
                entry_point: Some("fs_main"),
                targets: &[Some(wgpu::ColorTargetState {
                    format: config.format,
                    blend: Some(wgpu::BlendState::ALPHA_BLENDING),
                    write_mask: wgpu::ColorWrites::ALL,
                })],
                compilation_options: Default::default(),
            }),
            primitive: wgpu::PrimitiveState {
                topology: wgpu::PrimitiveTopology::TriangleList,
                cull_mode: None,
                ..Default::default()
            },
            depth_stencil: None,
            multisample: wgpu::MultisampleState::default(),
            multiview: None,
            cache: None,
        });

        let max_lines = 50000; // Line segments (for plots)
        let line_vertex_buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("Line Vertex Buffer"),
            size: (max_lines * 4 * std::mem::size_of::<LineVertex>()) as u64,
            usage: wgpu::BufferUsages::VERTEX | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let line_indices: Vec<u32> = (0..max_lines as u32)
            .flat_map(|i| {
                let base = i * 4;
                [base, base + 1, base + 2, base, base + 2, base + 3]
            })
            .collect();
        let line_index_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("Line Index Buffer"),
            contents: bytemuck::cast_slice(&line_indices),
            usage: wgpu::BufferUsages::INDEX,
        });

        // ===== Text Pipeline =====
        let text_shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("Text Shader"),
            source: wgpu::ShaderSource::Wgsl(include_str!("shaders/text.wgsl").into()),
        });

        let text_bind_group_layout =
            device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
                label: Some("Text Bind Group Layout"),
                entries: &[
                    wgpu::BindGroupLayoutEntry {
                        binding: 0,
                        visibility: wgpu::ShaderStages::FRAGMENT,
                        ty: wgpu::BindingType::Texture {
                            sample_type: wgpu::TextureSampleType::Float { filterable: true },
                            view_dimension: wgpu::TextureViewDimension::D2,
                            multisampled: false,
                        },
                        count: None,
                    },
                    wgpu::BindGroupLayoutEntry {
                        binding: 1,
                        visibility: wgpu::ShaderStages::FRAGMENT,
                        ty: wgpu::BindingType::Sampler(wgpu::SamplerBindingType::Filtering),
                        count: None,
                    },
                ],
            });

        let text_pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("Text Pipeline Layout"),
            bind_group_layouts: &[&uniform_bind_group_layout, &text_bind_group_layout],
            push_constant_ranges: &[],
        });

        let text_pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("Text Pipeline"),
            layout: Some(&text_pipeline_layout),
            vertex: wgpu::VertexState {
                module: &text_shader,
                entry_point: Some("vs_main"),
                buffers: &[TextVertex::desc()],
                compilation_options: Default::default(),
            },
            fragment: Some(wgpu::FragmentState {
                module: &text_shader,
                entry_point: Some("fs_main"),
                targets: &[Some(wgpu::ColorTargetState {
                    format: config.format,
                    blend: Some(wgpu::BlendState::ALPHA_BLENDING),
                    write_mask: wgpu::ColorWrites::ALL,
                })],
                compilation_options: Default::default(),
            }),
            primitive: wgpu::PrimitiveState {
                topology: wgpu::PrimitiveTopology::TriangleList,
                cull_mode: None,
                ..Default::default()
            },
            depth_stencil: None,
            multisample: wgpu::MultisampleState::default(),
            multiview: None,
            cache: None,
        });

        // Text texture (will hold rendered glyphs)
        let text_texture_size = wgpu::Extent3d {
            width: size.width.max(1),
            height: size.height.max(1),
            depth_or_array_layers: 1,
        };
        let text_texture = device.create_texture(&wgpu::TextureDescriptor {
            label: Some("Text Texture"),
            size: text_texture_size,
            mip_level_count: 1,
            sample_count: 1,
            dimension: wgpu::TextureDimension::D2,
            format: wgpu::TextureFormat::R8Unorm,
            usage: wgpu::TextureUsages::TEXTURE_BINDING | wgpu::TextureUsages::COPY_DST,
            view_formats: &[],
        });
        let text_texture_view = text_texture.create_view(&Default::default());

        let text_sampler = device.create_sampler(&wgpu::SamplerDescriptor {
            label: Some("Text Sampler"),
            mag_filter: wgpu::FilterMode::Linear,
            min_filter: wgpu::FilterMode::Linear,
            ..Default::default()
        });

        let text_bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("Text Bind Group"),
            layout: &text_bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: wgpu::BindingResource::TextureView(&text_texture_view),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: wgpu::BindingResource::Sampler(&text_sampler),
                },
            ],
        });

        let max_text_quads = 1000;
        let text_vertex_buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("Text Vertex Buffer"),
            size: (max_text_quads * 4 * std::mem::size_of::<TextVertex>()) as u64,
            usage: wgpu::BufferUsages::VERTEX | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let text_indices: Vec<u32> = (0..max_text_quads as u32)
            .flat_map(|i| {
                let base = i * 4;
                [base, base + 1, base + 2, base, base + 2, base + 3]
            })
            .collect();
        let text_index_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("Text Index Buffer"),
            contents: bytemuck::cast_slice(&text_indices),
            usage: wgpu::BufferUsages::INDEX,
        });

        let staging_size = (size.width * size.height) as usize;

        Self {
            surface,
            device,
            queue,
            config,
            size: (size.width, size.height),
            rect_pipeline,
            rect_vertices: Vec::with_capacity(max_rects * 4),
            rect_vertex_buffer,
            rect_index_buffer,
            max_rects,
            line_pipeline,
            line_vertices: Vec::with_capacity(max_lines * 4),
            line_vertex_buffer,
            line_index_buffer,
            max_lines,
            text_pipeline,
            text_renderer: TextRenderer::new(),
            text_items: Vec::new(),
            text_texture,
            text_texture_view,
            text_bind_group,
            text_vertex_buffer,
            text_index_buffer,
            max_text_quads,
            uniform_buffer,
            uniform_bind_group,
            text_staging_buffer: vec![0u8; staging_size],
            clear_color: wgpu::Color {
                r: 0.1,
                g: 0.1,
                b: 0.1,
                a: 1.0,
            },
        }
    }

    /// Resize the renderer
    pub fn resize(&mut self, width: u32, height: u32) {
        if width == 0 || height == 0 {
            return;
        }

        self.size = (width, height);
        self.config.width = width;
        self.config.height = height;
        self.surface.configure(&self.device, &self.config);

        // Update uniforms
        let uniforms = Uniforms {
            screen_size: [width as f32, height as f32],
            _padding: [0.0, 0.0],
        };
        self.queue
            .write_buffer(&self.uniform_buffer, 0, bytemuck::cast_slice(&[uniforms]));

        // Resize text staging buffer
        self.text_staging_buffer.resize((width * height) as usize, 0);

        // Recreate text texture with new size
        self.text_texture = self.device.create_texture(&wgpu::TextureDescriptor {
            label: Some("Text Texture"),
            size: wgpu::Extent3d {
                width,
                height,
                depth_or_array_layers: 1,
            },
            mip_level_count: 1,
            sample_count: 1,
            dimension: wgpu::TextureDimension::D2,
            format: wgpu::TextureFormat::R8Unorm,
            usage: wgpu::TextureUsages::TEXTURE_BINDING | wgpu::TextureUsages::COPY_DST,
            view_formats: &[],
        });
        self.text_texture_view = self.text_texture.create_view(&Default::default());

        // Recreate bind group with new texture view
        let text_bind_group_layout =
            self.device
                .create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
                    label: Some("Text Bind Group Layout"),
                    entries: &[
                        wgpu::BindGroupLayoutEntry {
                            binding: 0,
                            visibility: wgpu::ShaderStages::FRAGMENT,
                            ty: wgpu::BindingType::Texture {
                                sample_type: wgpu::TextureSampleType::Float { filterable: true },
                                view_dimension: wgpu::TextureViewDimension::D2,
                                multisampled: false,
                            },
                            count: None,
                        },
                        wgpu::BindGroupLayoutEntry {
                            binding: 1,
                            visibility: wgpu::ShaderStages::FRAGMENT,
                            ty: wgpu::BindingType::Sampler(wgpu::SamplerBindingType::Filtering),
                            count: None,
                        },
                    ],
                });

        let text_sampler = self.device.create_sampler(&wgpu::SamplerDescriptor {
            label: Some("Text Sampler"),
            mag_filter: wgpu::FilterMode::Linear,
            min_filter: wgpu::FilterMode::Linear,
            ..Default::default()
        });

        self.text_bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("Text Bind Group"),
            layout: &text_bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: wgpu::BindingResource::TextureView(&self.text_texture_view),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: wgpu::BindingResource::Sampler(&text_sampler),
                },
            ],
        });
    }

    /// Add a rectangle to the batch
    pub fn push_rect(
        &mut self,
        x: f32,
        y: f32,
        width: f32,
        height: f32,
        color: Color,
        border_radius: f32,
        border_width: f32,
        border_color: Color,
    ) {
        if self.rect_vertices.len() / 4 >= self.max_rects {
            return;
        }

        let fill_rgba = color_to_rgba(color);
        let border_rgba = color_to_rgba(border_color);

        let vertices = [
            RectVertex {
                position: [x, y],
                uv: [0.0, 0.0],
                color: fill_rgba,
                rect_pos: [x, y],
                rect_size: [width, height],
                border_radius,
                border_width,
                border_color: border_rgba,
            },
            RectVertex {
                position: [x + width, y],
                uv: [1.0, 0.0],
                color: fill_rgba,
                rect_pos: [x, y],
                rect_size: [width, height],
                border_radius,
                border_width,
                border_color: border_rgba,
            },
            RectVertex {
                position: [x + width, y + height],
                uv: [1.0, 1.0],
                color: fill_rgba,
                rect_pos: [x, y],
                rect_size: [width, height],
                border_radius,
                border_width,
                border_color: border_rgba,
            },
            RectVertex {
                position: [x, y + height],
                uv: [0.0, 1.0],
                color: fill_rgba,
                rect_pos: [x, y],
                rect_size: [width, height],
                border_radius,
                border_width,
                border_color: border_rgba,
            },
        ];

        self.rect_vertices.extend_from_slice(&vertices);
    }

    /// Add text to render
    pub fn push_text(
        &mut self,
        text: &str,
        x: f32,
        y: f32,
        width: f32,
        height: f32,
        font_size: f32,
        color: Color,
        align: TextAlign,
        weight: FontWeight,
    ) {
        self.text_items.push(TextItem {
            text: text.to_string(),
            x,
            y,
            width,
            height,
            font_size,
            color,
            align,
            weight,
        });
    }

    /// Clear all batches
    pub fn clear_batches(&mut self) {
        self.rect_vertices.clear();
        self.line_vertices.clear();
        self.text_items.clear();
    }

    /// Add a line segment to the batch
    pub fn push_line(
        &mut self,
        x1: f32,
        y1: f32,
        x2: f32,
        y2: f32,
        thickness: f32,
        color: Color,
    ) {
        if self.line_vertices.len() / 4 >= self.max_lines {
            return;
        }

        let color = color_to_rgba(color);
        let half_thick = thickness * 0.5 + 2.0; // Extra padding for anti-aliasing

        // Calculate perpendicular direction for quad expansion
        let dx = x2 - x1;
        let dy = y2 - y1;
        let len = (dx * dx + dy * dy).sqrt();
        if len < 0.001 {
            return;
        }

        // Perpendicular unit vector
        let px = -dy / len * half_thick;
        let py = dx / len * half_thick;

        // Extend along line direction for end caps
        let ex = dx / len * half_thick;
        let ey = dy / len * half_thick;

        // Create quad vertices (expanded rectangle around line)
        let vertices = [
            LineVertex {
                position: [x1 - ex + px, y1 - ey + py],
                line_start: [x1, y1],
                line_end: [x2, y2],
                color,
                thickness,
                _padding: 0.0,
            },
            LineVertex {
                position: [x2 + ex + px, y2 + ey + py],
                line_start: [x1, y1],
                line_end: [x2, y2],
                color,
                thickness,
                _padding: 0.0,
            },
            LineVertex {
                position: [x2 + ex - px, y2 + ey - py],
                line_start: [x1, y1],
                line_end: [x2, y2],
                color,
                thickness,
                _padding: 0.0,
            },
            LineVertex {
                position: [x1 - ex - px, y1 - ey - py],
                line_start: [x1, y1],
                line_end: [x2, y2],
                color,
                thickness,
                _padding: 0.0,
            },
        ];

        self.line_vertices.extend_from_slice(&vertices);
    }

    /// Render all batched geometry
    pub fn render(&mut self) -> Result<(), wgpu::SurfaceError> {
        let output = self.surface.get_current_texture()?;
        let view = output
            .texture
            .create_view(&wgpu::TextureViewDescriptor::default());

        // Render text to staging buffer first
        self.render_text_to_staging();

        // Upload text texture
        if !self.text_items.is_empty() {
            self.queue.write_texture(
                wgpu::ImageCopyTexture {
                    texture: &self.text_texture,
                    mip_level: 0,
                    origin: wgpu::Origin3d::ZERO,
                    aspect: wgpu::TextureAspect::All,
                },
                &self.text_staging_buffer,
                wgpu::ImageDataLayout {
                    offset: 0,
                    bytes_per_row: Some(self.size.0),
                    rows_per_image: Some(self.size.1),
                },
                wgpu::Extent3d {
                    width: self.size.0,
                    height: self.size.1,
                    depth_or_array_layers: 1,
                },
            );
        }

        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("Render Encoder"),
            });

        // Upload rectangle vertices
        if !self.rect_vertices.is_empty() {
            self.queue.write_buffer(
                &self.rect_vertex_buffer,
                0,
                bytemuck::cast_slice(&self.rect_vertices),
            );
        }

        // Upload line vertices
        if !self.line_vertices.is_empty() {
            self.queue.write_buffer(
                &self.line_vertex_buffer,
                0,
                bytemuck::cast_slice(&self.line_vertices),
            );
        }

        {
            let mut render_pass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
                label: Some("Main Render Pass"),
                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                    view: &view,
                    resolve_target: None,
                    ops: wgpu::Operations {
                        load: wgpu::LoadOp::Clear(self.clear_color),
                        store: wgpu::StoreOp::Store,
                    },
                })],
                depth_stencil_attachment: None,
                timestamp_writes: None,
                occlusion_query_set: None,
            });

            // Draw rectangles
            if !self.rect_vertices.is_empty() {
                let num_rects = self.rect_vertices.len() / 4;
                render_pass.set_pipeline(&self.rect_pipeline);
                render_pass.set_bind_group(0, &self.uniform_bind_group, &[]);
                render_pass.set_vertex_buffer(0, self.rect_vertex_buffer.slice(..));
                render_pass.set_index_buffer(
                    self.rect_index_buffer.slice(..),
                    wgpu::IndexFormat::Uint32,
                );
                render_pass.draw_indexed(0..(num_rects * 6) as u32, 0, 0..1);
            }

            // Draw lines
            if !self.line_vertices.is_empty() {
                let num_lines = self.line_vertices.len() / 4;
                render_pass.set_pipeline(&self.line_pipeline);
                render_pass.set_bind_group(0, &self.uniform_bind_group, &[]);
                render_pass.set_vertex_buffer(0, self.line_vertex_buffer.slice(..));
                render_pass.set_index_buffer(
                    self.line_index_buffer.slice(..),
                    wgpu::IndexFormat::Uint32,
                );
                render_pass.draw_indexed(0..(num_lines * 6) as u32, 0, 0..1);
            }

            // Draw text (one fullscreen quad with text texture)
            if !self.text_items.is_empty() {
                let text_vertices = self.create_text_quad();
                self.queue.write_buffer(
                    &self.text_vertex_buffer,
                    0,
                    bytemuck::cast_slice(&text_vertices),
                );

                render_pass.set_pipeline(&self.text_pipeline);
                render_pass.set_bind_group(0, &self.uniform_bind_group, &[]);
                render_pass.set_bind_group(1, &self.text_bind_group, &[]);
                render_pass.set_vertex_buffer(0, self.text_vertex_buffer.slice(..));
                render_pass.set_index_buffer(
                    self.text_index_buffer.slice(..),
                    wgpu::IndexFormat::Uint32,
                );
                render_pass.draw_indexed(0..6, 0, 0..1);
            }
        }

        self.queue.submit(std::iter::once(encoder.finish()));
        output.present();

        Ok(())
    }

    /// Render text items to the staging buffer
    fn render_text_to_staging(&mut self) {
        // Clear staging buffer
        self.text_staging_buffer.fill(0);

        let width = self.size.0;
        let height = self.size.1;

        // Clone text items to avoid borrow conflict
        let items: Vec<_> = self.text_items.iter().map(|item| {
            (
                item.text.clone(),
                item.x as i32,
                item.y as i32,
                item.width as u32,
                item.height as u32,
                item.font_size,
                item.align,
                item.weight,
            )
        }).collect();

        for (text, x, y, max_width, max_height, font_size, align, weight) in items {
            self.render_text_item_to_staging(
                &text,
                x,
                y,
                max_width,
                max_height,
                font_size,
                align,
                weight,
                width,
                height,
            );
        }
    }

    fn render_text_item_to_staging(
        &mut self,
        text: &str,
        x: i32,
        y: i32,
        max_width: u32,
        max_height: u32,
        font_size: f32,
        align: TextAlign,
        weight: FontWeight,
        buffer_width: u32,
        buffer_height: u32,
    ) {
        // Measure text for alignment
        let (text_width, _) = self.text_renderer.measure(text, font_size, weight);

        let start_x = match align {
            TextAlign::Left => x as f32,
            TextAlign::Center => x as f32 + (max_width as f32 - text_width) / 2.0,
            TextAlign::Right => x as f32 + max_width as f32 - text_width,
        };

        let baseline_y = y as f32 + (max_height as f32 + font_size * 0.7) / 2.0;
        let mut cursor_x = start_x;

        let font = self.text_renderer.get_font(weight);

        for c in text.chars() {
            let (metrics, bitmap) = font.rasterize(c, font_size);

            let gx = (cursor_x + metrics.xmin as f32) as i32;
            let gy = (baseline_y - metrics.ymin as f32 - metrics.height as f32) as i32;

            // Blit glyph to staging buffer
            for gy_offset in 0..metrics.height {
                for gx_offset in 0..metrics.width {
                    let px = gx + gx_offset as i32;
                    let py = gy + gy_offset as i32;

                    if px < 0 || py < 0 || px >= buffer_width as i32 || py >= buffer_height as i32 {
                        continue;
                    }

                    let glyph_idx = gy_offset * metrics.width + gx_offset;
                    let alpha = bitmap.get(glyph_idx).copied().unwrap_or(0);

                    if alpha > 0 {
                        let buffer_idx = (py as u32 * buffer_width + px as u32) as usize;
                        if buffer_idx < self.text_staging_buffer.len() {
                            // Blend with existing value
                            let existing = self.text_staging_buffer[buffer_idx] as u16;
                            let blended = (existing + alpha as u16).min(255) as u8;
                            self.text_staging_buffer[buffer_idx] = blended;
                        }
                    }
                }
            }

            cursor_x += metrics.advance_width;
        }
    }

    /// Create a fullscreen quad for text rendering
    fn create_text_quad(&self) -> [TextVertex; 4] {
        let w = self.size.0 as f32;
        let h = self.size.1 as f32;

        // Get average text color (simplified - use white for now)
        let color = [1.0, 1.0, 1.0, 1.0];

        [
            TextVertex {
                position: [0.0, 0.0],
                uv: [0.0, 0.0],
                color,
            },
            TextVertex {
                position: [w, 0.0],
                uv: [1.0, 0.0],
                color,
            },
            TextVertex {
                position: [w, h],
                uv: [1.0, 1.0],
                color,
            },
            TextVertex {
                position: [0.0, h],
                uv: [0.0, 1.0],
                color,
            },
        ]
    }

    /// Render the UI tree
    pub fn render_tree(&mut self, tree: &UiTree, root: NodeId, state: RenderState) {
        self.clear_batches();
        self.collect_nodes(tree, root, &state);
        let _ = self.render();
    }

    /// Collect all nodes into vertex batches
    fn collect_nodes(&mut self, tree: &UiTree, node_id: NodeId, state: &RenderState) {
        let node = match tree.get(node_id) {
            Some(n) => n,
            None => return,
        };

        let layout = &node.layout;
        let style = &node.style;

        let x = layout.x;
        let y = layout.y;
        let w = layout.width;
        let h = layout.height;

        let is_hovered = state.hovered == Some(node_id);
        let is_pressed = state.pressed == Some(node_id);

        // Draw background
        if let Some(bg) = style.background_color {
            let bg = if is_pressed {
                Self::darken_color(bg, 0.2)
            } else if is_hovered {
                Self::lighten_color(bg, 0.15)
            } else {
                bg
            };

            let border_color = style.border_color.unwrap_or(0);
            let border_width = if style.border_width > 0.0 {
                style.border_width
            } else {
                0.0
            };

            self.push_rect(x, y, w, h, bg, style.border_radius, border_width, border_color);
        }

        // Hover outline for buttons
        if is_hovered && matches!(node.content, NodeContent::Button { .. }) {
            self.push_rect(x, y, w, h, 0x00000000, style.border_radius, 2.0, 0x40FFFFFF);
        }

        // Handle content types
        match &node.content {
            NodeContent::Container => {}
            NodeContent::Text(text) => {
                let color = style.text_color.unwrap_or(0xFFFFFFFF);
                let font_size = if style.font_size > 0.0 { style.font_size } else { 14.0 };
                let weight = if style.font_bold { FontWeight::Bold } else { FontWeight::Regular };
                let align = match style.text_align.as_deref() {
                    Some("center") => TextAlign::Center,
                    Some("right") => TextAlign::Right,
                    _ => TextAlign::Left,
                };
                self.push_text(text, x, y, w, h, font_size, color, align, weight);
            }
            NodeContent::Button { label, .. } => {
                let color = style.text_color.unwrap_or(0xFFFFFFFF);
                let font_size = if style.font_size > 0.0 { style.font_size } else { 14.0 };
                let weight = if style.font_bold { FontWeight::Bold } else { FontWeight::Regular };
                self.push_text(label, x, y, w, h, font_size, color, TextAlign::Center, weight);
            }
            NodeContent::Slider { min, max, value, .. } => {
                self.render_slider(x, y, w, h, *min, *max, *value, style, is_hovered);
            }
            NodeContent::Checkbox { checked, label, .. } => {
                self.render_checkbox(x, y, w, h, *checked, label, style, is_hovered);
            }
            NodeContent::ProgressBar { progress } => {
                self.render_progress_bar(x, y, w, h, *progress, style);
            }
            NodeContent::Separator => {
                let color = style.background_color.unwrap_or(0xFF4B5563);
                self.push_rect(x, y, w, h.max(1.0), color, 0.0, 0.0, 0);
            }
            NodeContent::TextInput { placeholder, value, cursor, .. } => {
                let is_focused = state.focused == Some(node_id);
                self.render_text_input(x, y, w, h, placeholder, value, *cursor, style, is_hovered, is_focused);
            }
            NodeContent::Plot { title, series, .. } => {
                self.render_plot(x, y, w, h, title, series, style);
            }
        }

        // Render children
        for &child_id in &node.children {
            self.collect_nodes(tree, child_id, state);
        }
    }

    fn render_slider(&mut self, x: f32, y: f32, w: f32, h: f32, min: f64, max: f64, value: f64, style: &NodeStyle, is_hovered: bool) {
        let track_height = 6.0;
        let track_y = y + (h - track_height) / 2.0;
        let track_bg = style.background_color.unwrap_or(0xFF374151);
        self.push_rect(x, track_y, w, track_height, track_bg, 3.0, 0.0, 0);

        let range = max - min;
        let normalized = if range > 0.0 { ((value - min) / range).clamp(0.0, 1.0) } else { 0.0 };
        let fill_width = (w as f64 * normalized) as f32;
        if fill_width > 0.0 {
            self.push_rect(x, track_y, fill_width, track_height, 0xFF3B82F6, 3.0, 0.0, 0);
        }

        let thumb_radius = 8.0;
        let thumb_x = x + fill_width - thumb_radius;
        let thumb_y = y + h / 2.0 - thumb_radius;
        let thumb_color = if is_hovered { 0xFFFFFFFF } else { 0xFFE5E7EB };
        self.push_rect(thumb_x, thumb_y, thumb_radius * 2.0, thumb_radius * 2.0, thumb_color, thumb_radius, 0.0, 0);
    }

    fn render_checkbox(&mut self, x: f32, y: f32, _w: f32, h: f32, checked: bool, label: &str, style: &NodeStyle, is_hovered: bool) {
        let box_size = 18.0;
        let box_y = y + (h - box_size) / 2.0;
        let box_bg = if checked { 0xFF3B82F6 } else { 0xFF374151 };
        let box_bg = if is_hovered { Self::lighten_color(box_bg, 0.15) } else { box_bg };
        let border_color = if is_hovered { 0xFF60A5FA } else { 0xFF4B5563 };
        self.push_rect(x, box_y, box_size, box_size, box_bg, 4.0, 1.0, border_color);

        if checked {
            self.push_rect(x + 5.0, box_y + 5.0, 8.0, 8.0, 0xFFFFFFFF, 2.0, 0.0, 0);
        }

        // Label
        let color = style.text_color.unwrap_or(0xFFFFFFFF);
        let font_size = if style.font_size > 0.0 { style.font_size } else { 14.0 };
        self.push_text(label, x + box_size + 8.0, y, 200.0, h, font_size, color, TextAlign::Left, FontWeight::Regular);
    }

    fn render_progress_bar(&mut self, x: f32, y: f32, w: f32, h: f32, progress: f32, style: &NodeStyle) {
        let track_bg = style.background_color.unwrap_or(0xFF374151);
        let radius = style.border_radius.min(h / 2.0);
        self.push_rect(x, y, w, h, track_bg, radius, 0.0, 0);

        let fill_width = w * progress.clamp(0.0, 1.0);
        if fill_width > 0.0 {
            self.push_rect(x, y, fill_width, h, 0xFF3B82F6, radius, 0.0, 0);
        }
    }

    fn render_text_input(&mut self, x: f32, y: f32, w: f32, h: f32, placeholder: &str, value: &str, cursor: usize, style: &NodeStyle, is_hovered: bool, is_focused: bool) {
        let bg_color = style.background_color.unwrap_or(0xFF2D2D2D);
        let bg_color = if is_focused {
            Self::lighten_color(bg_color, 0.15)
        } else if is_hovered {
            Self::lighten_color(bg_color, 0.1)
        } else {
            bg_color
        };
        let border_color = if is_focused {
            0xFF3B82F6 // Blue when focused
        } else if is_hovered {
            0xFF60A5FA
        } else {
            style.border_color.unwrap_or(0xFF4B5563)
        };
        let border_width = if is_focused { 2.0 } else { 1.0 };
        self.push_rect(x, y, w, h, bg_color, style.border_radius, border_width, border_color);

        let font_size = if style.font_size > 0.0 { style.font_size } else { 14.0 };

        if value.is_empty() {
            // Show placeholder when empty
            self.push_text(placeholder, x + 8.0, y, w - 16.0, h, font_size, 0xFF9CA3AF, TextAlign::Left, FontWeight::Regular);
        } else {
            // Show actual value
            let text_color = style.text_color.unwrap_or(0xFFFFFFFF);
            self.push_text(value, x + 8.0, y, w - 16.0, h, font_size, text_color, TextAlign::Left, FontWeight::Regular);
        }

        // Draw cursor when focused
        if is_focused {
            let text_before_cursor = &value[..cursor.min(value.len())];
            let (cursor_offset, _) = self.text_renderer.measure(text_before_cursor, font_size, FontWeight::Regular);
            let cursor_x = x + 8.0 + cursor_offset;
            let cursor_y = y + (h - font_size) / 2.0;
            // Blinking cursor (simple solid line for now)
            self.push_rect(cursor_x, cursor_y, 2.0, font_size, 0xFFFFFFFF, 0.0, 0.0, 0);
        }
    }

    fn render_plot(&mut self, x: f32, y: f32, w: f32, h: f32, title: &str, series: &[PlotSeries], style: &NodeStyle) {
        let bg_color = style.background_color.unwrap_or(0xFF1F2937);
        self.push_rect(x, y, w, h, bg_color, style.border_radius, 0.0, 0);

        // Title
        self.push_text(title, x + 8.0, y + 4.0, w - 16.0, 24.0, 14.0, 0xFFFFFFFF, TextAlign::Left, FontWeight::Bold);

        let plot_x = x + 40.0;
        let plot_y = y + 32.0;
        let plot_w = w - 50.0;
        let plot_h = h - 56.0;

        if plot_w <= 0.0 || plot_h <= 0.0 || series.is_empty() {
            return;
        }

        // Find bounds
        let (mut min_x, mut max_x, mut min_y, mut max_y) = (f64::MAX, f64::MIN, f64::MAX, f64::MIN);
        for s in series {
            for &(px, py) in &s.data {
                min_x = min_x.min(px);
                max_x = max_x.max(px);
                min_y = min_y.min(py);
                max_y = max_y.max(py);
            }
        }
        let range_x = (max_x - min_x).max(0.001);
        let range_y = (max_y - min_y).max(0.001);

        // Grid lines
        for i in 0..=4 {
            let gy = plot_y + (plot_h * i as f32) / 4.0;
            self.push_rect(plot_x, gy, plot_w, 1.0, 0xFF374151, 0.0, 0.0, 0);
        }

        // Draw series
        for s in series {
            let radius = s.radius.max(2.0);

            // Calculate screen coordinates for all points
            let screen_points: Vec<(f32, f32)> = s.data.iter().map(|&(px, py)| {
                let sx = plot_x + ((px - min_x) / range_x * plot_w as f64) as f32;
                let sy = plot_y + plot_h - ((py - min_y) / range_y * plot_h as f64) as f32;
                (sx, sy)
            }).collect();

            match s.kind {
                crate::node::PlotKind::Line => {
                    // Draw lines connecting consecutive points
                    for pair in screen_points.windows(2) {
                        let (x1, y1) = pair[0];
                        let (x2, y2) = pair[1];
                        self.push_line(x1, y1, x2, y2, 2.0, s.color);
                    }
                    // Draw small points at each data point
                    for &(sx, sy) in &screen_points {
                        let point_radius = radius * 0.6;
                        self.push_rect(sx - point_radius, sy - point_radius, point_radius * 2.0, point_radius * 2.0, s.color, point_radius, 0.0, 0);
                    }
                }
                crate::node::PlotKind::Scatter => {
                    // Draw only points
                    for &(sx, sy) in &screen_points {
                        self.push_rect(sx - radius, sy - radius, radius * 2.0, radius * 2.0, s.color, radius, 0.0, 0);
                    }
                }
            }
        }

        // Border
        self.push_rect(plot_x, plot_y, plot_w, plot_h, 0x00000000, 0.0, 1.0, 0xFF4B5563);
    }

    fn lighten_color(color: Color, factor: f32) -> Color {
        let a = (color >> 24) & 0xFF;
        let r = ((color >> 16) & 0xFF) as f32;
        let g = ((color >> 8) & 0xFF) as f32;
        let b = (color & 0xFF) as f32;
        let r = (r + (255.0 - r) * factor).min(255.0) as u32;
        let g = (g + (255.0 - g) * factor).min(255.0) as u32;
        let b = (b + (255.0 - b) * factor).min(255.0) as u32;
        (a << 24) | (r << 16) | (g << 8) | b
    }

    fn darken_color(color: Color, factor: f32) -> Color {
        let a = (color >> 24) & 0xFF;
        let r = ((color >> 16) & 0xFF) as f32;
        let g = ((color >> 8) & 0xFF) as f32;
        let b = (color & 0xFF) as f32;
        let r = (r * (1.0 - factor)).max(0.0) as u32;
        let g = (g * (1.0 - factor)).max(0.0) as u32;
        let b = (b * (1.0 - factor)).max(0.0) as u32;
        (a << 24) | (r << 16) | (g << 8) | b
    }
}
