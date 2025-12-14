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
    pub position: [f32; 2],   // Vertex position
    pub line_start: [f32; 2], // Line segment start
    pub line_end: [f32; 2],   // Line segment end
    pub color: [f32; 4],      // Line color
    pub thickness: f32,       // Line thickness
    pub _padding: f32,        // Padding for alignment
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
#[allow(dead_code)]
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
    #[allow(dead_code)]
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
        self.text_staging_buffer
            .resize((width * height) as usize, 0);

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
    pub fn push_line(&mut self, x1: f32, y1: f32, x2: f32, y2: f32, thickness: f32, color: Color) {
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
                render_pass
                    .set_index_buffer(self.rect_index_buffer.slice(..), wgpu::IndexFormat::Uint32);
                render_pass.draw_indexed(0..(num_rects * 6) as u32, 0, 0..1);
            }

            // Draw lines
            if !self.line_vertices.is_empty() {
                let num_lines = self.line_vertices.len() / 4;
                render_pass.set_pipeline(&self.line_pipeline);
                render_pass.set_bind_group(0, &self.uniform_bind_group, &[]);
                render_pass.set_vertex_buffer(0, self.line_vertex_buffer.slice(..));
                render_pass
                    .set_index_buffer(self.line_index_buffer.slice(..), wgpu::IndexFormat::Uint32);
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
                render_pass
                    .set_index_buffer(self.text_index_buffer.slice(..), wgpu::IndexFormat::Uint32);
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
        let items: Vec<_> = self
            .text_items
            .iter()
            .map(|item| {
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
            })
            .collect();

        for (text, x, y, max_width, max_height, font_size, align, weight) in items {
            self.render_text_item_to_staging(
                &text, x, y, max_width, max_height, font_size, align, weight, width, height,
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

            self.push_rect(
                x,
                y,
                w,
                h,
                bg,
                style.border_radius,
                border_width,
                border_color,
            );
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
                let font_size = if style.font_size > 0.0 {
                    style.font_size
                } else {
                    14.0
                };
                let weight = if style.font_bold {
                    FontWeight::Bold
                } else {
                    FontWeight::Regular
                };
                let align = match style.text_align.as_deref() {
                    Some("center") => TextAlign::Center,
                    Some("right") => TextAlign::Right,
                    _ => TextAlign::Left,
                };
                self.push_text(text, x, y, w, h, font_size, color, align, weight);
            }
            NodeContent::Button { label, .. } => {
                let color = style.text_color.unwrap_or(0xFFFFFFFF);
                let font_size = if style.font_size > 0.0 {
                    style.font_size
                } else {
                    14.0
                };
                let weight = if style.font_bold {
                    FontWeight::Bold
                } else {
                    FontWeight::Regular
                };
                self.push_text(
                    label,
                    x,
                    y,
                    w,
                    h,
                    font_size,
                    color,
                    TextAlign::Center,
                    weight,
                );
            }
            NodeContent::Slider {
                min, max, value, ..
            } => {
                self.render_slider(x, y, w, h, *min, *max, *value, style, is_hovered);
            }
            NodeContent::Checkbox { checked, label, .. } => {
                self.render_checkbox(x, y, w, h, *checked, label, style, is_hovered);
            }
            NodeContent::ProgressBar { progress } => {
                self.render_progress_bar(x, y, w, h, *progress, style);
            }
            NodeContent::RadioButton {
                label,
                index,
                selected,
                ..
            } => {
                self.render_radio_button(x, y, w, h, label, *index, *selected, style, is_hovered);
            }
            NodeContent::Separator => {
                let color = style.background_color.unwrap_or(0xFF4B5563);
                self.push_rect(x, y, w, h.max(1.0), color, 0.0, 0.0, 0);
            }
            NodeContent::TextInput {
                placeholder,
                value,
                cursor,
                ..
            } => {
                let is_focused = state.focused == Some(node_id);
                self.render_text_input(
                    x,
                    y,
                    w,
                    h,
                    placeholder,
                    value,
                    *cursor,
                    style,
                    is_hovered,
                    is_focused,
                );
            }
            NodeContent::Plot {
                title,
                x_label,
                y_label,
                series,
                x_range,
                y_range,
            } => {
                self.render_plot(x, y, w, h, title, x_label, y_label, series, *x_range, *y_range, style);
            }
            NodeContent::Dropdown {
                options,
                selected,
                open,
                placeholder,
                ..
            } => {
                self.render_dropdown(x, y, w, h, options, *selected, *open, placeholder, style, is_hovered);
            }
            NodeContent::TabHeader { tabs, active, .. } => {
                self.render_tab_header(x, y, w, h, tabs, *active, style, is_hovered);
            }
            NodeContent::Tooltip { text, visible } => {
                if *visible {
                    self.render_tooltip(x, y, text, style);
                }
            }
            NodeContent::Modal { visible, title, .. } => {
                if *visible {
                    self.render_modal_overlay(x, y, w, h, title, style);
                }
            }
        }

        // Render children
        for &child_id in &node.children {
            self.collect_nodes(tree, child_id, state);
        }
    }

    fn render_slider(
        &mut self,
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        min: f64,
        max: f64,
        value: f64,
        style: &NodeStyle,
        is_hovered: bool,
    ) {
        let track_height = 6.0;
        let track_y = y + (h - track_height) / 2.0;
        let track_bg = style.background_color.unwrap_or(0xFF374151);
        self.push_rect(x, track_y, w, track_height, track_bg, 3.0, 0.0, 0);

        let range = max - min;
        let normalized = if range > 0.0 {
            ((value - min) / range).clamp(0.0, 1.0)
        } else {
            0.0
        };
        let fill_width = (w as f64 * normalized) as f32;
        if fill_width > 0.0 {
            self.push_rect(
                x,
                track_y,
                fill_width,
                track_height,
                0xFF3B82F6,
                3.0,
                0.0,
                0,
            );
        }

        let thumb_radius = 8.0;
        let thumb_x = x + fill_width - thumb_radius;
        let thumb_y = y + h / 2.0 - thumb_radius;
        let thumb_color = if is_hovered { 0xFFFFFFFF } else { 0xFFE5E7EB };
        self.push_rect(
            thumb_x,
            thumb_y,
            thumb_radius * 2.0,
            thumb_radius * 2.0,
            thumb_color,
            thumb_radius,
            0.0,
            0,
        );
    }

    fn render_checkbox(
        &mut self,
        x: f32,
        y: f32,
        _w: f32,
        h: f32,
        checked: bool,
        label: &str,
        style: &NodeStyle,
        is_hovered: bool,
    ) {
        let box_size = 18.0;
        let box_y = y + (h - box_size) / 2.0;
        let box_bg = if checked { 0xFF3B82F6 } else { 0xFF374151 };
        let box_bg = if is_hovered {
            Self::lighten_color(box_bg, 0.15)
        } else {
            box_bg
        };
        let border_color = if is_hovered { 0xFF60A5FA } else { 0xFF4B5563 };
        self.push_rect(x, box_y, box_size, box_size, box_bg, 4.0, 1.0, border_color);

        if checked {
            self.push_rect(x + 5.0, box_y + 5.0, 8.0, 8.0, 0xFFFFFFFF, 2.0, 0.0, 0);
        }

        // Label
        let color = style.text_color.unwrap_or(0xFFFFFFFF);
        let font_size = if style.font_size > 0.0 {
            style.font_size
        } else {
            14.0
        };
        self.push_text(
            label,
            x + box_size + 8.0,
            y,
            200.0,
            h,
            font_size,
            color,
            TextAlign::Left,
            FontWeight::Regular,
        );
    }

    fn render_radio_button(
        &mut self,
        x: f32,
        y: f32,
        _w: f32,
        h: f32,
        label: &str,
        index: usize,
        selected: usize,
        style: &NodeStyle,
        is_hovered: bool,
    ) {
        let is_selected = index == selected;
        let circle_size = 18.0;
        let circle_y = y + (h - circle_size) / 2.0;
        let circle_x = x;

        // Outer circle (border)
        let bg_color = if is_selected { 0xFF3B82F6 } else { 0xFF374151 };
        let bg_color = if is_hovered {
            Self::lighten_color(bg_color, 0.15)
        } else {
            bg_color
        };
        let border_color = if is_hovered { 0xFF60A5FA } else { 0xFF4B5563 };

        // Draw outer circle (use high border_radius for circle effect)
        self.push_rect(
            circle_x,
            circle_y,
            circle_size,
            circle_size,
            bg_color,
            circle_size / 2.0, // Full circle
            1.0,
            border_color,
        );

        // Inner dot when selected
        if is_selected {
            let dot_size = 8.0;
            let dot_offset = (circle_size - dot_size) / 2.0;
            self.push_rect(
                circle_x + dot_offset,
                circle_y + dot_offset,
                dot_size,
                dot_size,
                0xFFFFFFFF,
                dot_size / 2.0, // Full circle
                0.0,
                0,
            );
        }

        // Label
        let color = style.text_color.unwrap_or(0xFFFFFFFF);
        let font_size = if style.font_size > 0.0 {
            style.font_size
        } else {
            14.0
        };
        self.push_text(
            label,
            x + circle_size + 8.0,
            y,
            200.0,
            h,
            font_size,
            color,
            TextAlign::Left,
            FontWeight::Regular,
        );
    }

    fn render_progress_bar(
        &mut self,
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        progress: f32,
        style: &NodeStyle,
    ) {
        let track_bg = style.background_color.unwrap_or(0xFF374151);
        let radius = style.border_radius.min(h / 2.0);
        self.push_rect(x, y, w, h, track_bg, radius, 0.0, 0);

        let fill_width = w * progress.clamp(0.0, 1.0);
        if fill_width > 0.0 {
            self.push_rect(x, y, fill_width, h, 0xFF3B82F6, radius, 0.0, 0);
        }
    }

    fn render_text_input(
        &mut self,
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        placeholder: &str,
        value: &str,
        cursor: usize,
        style: &NodeStyle,
        is_hovered: bool,
        is_focused: bool,
    ) {
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
        self.push_rect(
            x,
            y,
            w,
            h,
            bg_color,
            style.border_radius,
            border_width,
            border_color,
        );

        let font_size = if style.font_size > 0.0 {
            style.font_size
        } else {
            14.0
        };

        if value.is_empty() {
            // Show placeholder when empty
            self.push_text(
                placeholder,
                x + 8.0,
                y,
                w - 16.0,
                h,
                font_size,
                0xFF9CA3AF,
                TextAlign::Left,
                FontWeight::Regular,
            );
        } else {
            // Show actual value
            let text_color = style.text_color.unwrap_or(0xFFFFFFFF);
            self.push_text(
                value,
                x + 8.0,
                y,
                w - 16.0,
                h,
                font_size,
                text_color,
                TextAlign::Left,
                FontWeight::Regular,
            );
        }

        // Draw cursor when focused
        if is_focused {
            let text_before_cursor = &value[..cursor.min(value.len())];
            let (cursor_offset, _) =
                self.text_renderer
                    .measure(text_before_cursor, font_size, FontWeight::Regular);
            let cursor_x = x + 8.0 + cursor_offset;
            let cursor_y = y + (h - font_size) / 2.0;
            // Blinking cursor (simple solid line for now)
            self.push_rect(cursor_x, cursor_y, 2.0, font_size, 0xFFFFFFFF, 0.0, 0.0, 0);
        }
    }

    fn render_plot(
        &mut self,
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        title: &str,
        x_label: &str,
        y_label: &str,
        series: &[PlotSeries],
        fixed_x_range: Option<(f64, f64)>,
        fixed_y_range: Option<(f64, f64)>,
        style: &NodeStyle,
    ) {
        let bg_color = style.background_color.unwrap_or(0xFF1F2937);
        self.push_rect(x, y, w, h, bg_color, style.border_radius, 0.0, 0);

        // Layout constants
        let title_height = if title.is_empty() { 8.0 } else { 28.0 };
        let y_axis_width = 55.0; // Space for Y axis labels
        let x_axis_height = 40.0; // Space for X axis labels
        let padding = 8.0;

        // Title (centered)
        if !title.is_empty() {
            self.push_text(
                title,
                x + padding,
                y + 4.0,
                w - padding * 2.0,
                24.0,
                14.0,
                0xFFFFFFFF,
                TextAlign::Center,
                FontWeight::Bold,
            );
        }

        // Plot area
        let plot_x = x + y_axis_width;
        let plot_y = y + title_height;
        let plot_w = w - y_axis_width - padding;
        let plot_h = h - title_height - x_axis_height;

        if plot_w <= 0.0 || plot_h <= 0.0 || series.is_empty() {
            return;
        }

        // Determine axis ranges: use fixed ranges if provided, otherwise auto-calculate from data
        let (min_x, max_x) = if let Some((lo, hi)) = fixed_x_range {
            (lo, hi)
        } else {
            // Auto-calculate from data
            let (mut lo, mut hi) = (f64::MAX, f64::MIN);
            for s in series {
                for &(px, _) in &s.data {
                    lo = lo.min(px);
                    hi = hi.max(px);
                }
            }
            (lo, hi)
        };

        let (min_y, max_y) = if let Some((lo, hi)) = fixed_y_range {
            (lo, hi)
        } else {
            // Auto-calculate from data with padding
            let (mut lo, mut hi) = (f64::MAX, f64::MIN);
            for s in series {
                for &(_, py) in &s.data {
                    lo = lo.min(py);
                    hi = hi.max(py);
                }
            }
            // Add some padding to bounds so data doesn't touch edges
            let y_margin = (hi - lo) * 0.05;
            (lo - y_margin, hi + y_margin)
        };

        let range_x = (max_x - min_x).max(0.001);
        let range_y = (max_y - min_y).max(0.001);

        let grid_color = 0xFF374151;
        let label_color = 0xFF9CA3AF;
        let num_grid_lines = 5;

        // Draw horizontal grid lines with Y-axis tick values
        for i in 0..=num_grid_lines {
            let ratio = i as f32 / num_grid_lines as f32;
            let gy = plot_y + plot_h - (plot_h * ratio);

            // Grid line
            self.push_rect(plot_x, gy, plot_w, 1.0, grid_color, 0.0, 0.0, 0);

            // Y-axis tick value
            let y_val = min_y + (range_y * ratio as f64);
            let y_text = Self::format_axis_value(y_val);
            self.push_text(
                &y_text,
                x + 2.0,
                gy - 7.0,
                y_axis_width - 6.0,
                14.0,
                10.0,
                label_color,
                TextAlign::Right,
                FontWeight::Regular,
            );
        }

        // Draw vertical grid lines with X-axis tick values
        for i in 0..=num_grid_lines {
            let ratio = i as f32 / num_grid_lines as f32;
            let gx = plot_x + (plot_w * ratio);

            // Grid line
            self.push_rect(gx, plot_y, 1.0, plot_h, grid_color, 0.0, 0.0, 0);

            // X-axis tick value
            let x_val = min_x + (range_x * ratio as f64);
            let x_text = Self::format_axis_value(x_val);
            self.push_text(
                &x_text,
                gx - 20.0,
                plot_y + plot_h + 4.0,
                40.0,
                14.0,
                10.0,
                label_color,
                TextAlign::Center,
                FontWeight::Regular,
            );
        }

        // X-axis label (centered below plot)
        if !x_label.is_empty() {
            self.push_text(
                x_label,
                plot_x,
                plot_y + plot_h + 22.0,
                plot_w,
                16.0,
                11.0,
                0xFFD1D5DB,
                TextAlign::Center,
                FontWeight::Regular,
            );
        }

        // Y-axis label (rotated text is complex, so we'll place it vertically as individual chars or just at top)
        // For simplicity, place it at the top-left of the Y axis area
        if !y_label.is_empty() {
            self.push_text(
                y_label,
                x + 2.0,
                plot_y - 2.0,
                y_axis_width - 4.0,
                14.0,
                10.0,
                0xFFD1D5DB,
                TextAlign::Left,
                FontWeight::Regular,
            );
        }

        // Draw series data
        for s in series {
            let radius = s.radius.max(2.0);

            match s.kind {
                crate::node::PlotKind::Line => {
                    let mut prev_point: Option<(f32, f32)> = None;

                    for &(px, py) in &s.data {
                        let sx = plot_x + ((px - min_x) / range_x * plot_w as f64) as f32;
                        let sy = plot_y + plot_h - ((py - min_y) / range_y * plot_h as f64) as f32;

                        // Clamp to plot area
                        let sx = sx.clamp(plot_x, plot_x + plot_w);
                        let sy = sy.clamp(plot_y, plot_y + plot_h);

                        // Draw line from previous point
                        if let Some((prev_x, prev_y)) = prev_point {
                            self.push_line(prev_x, prev_y, sx, sy, 2.0, s.color);
                        }

                        prev_point = Some((sx, sy));
                    }
                }
                crate::node::PlotKind::Scatter => {
                    for &(px, py) in &s.data {
                        let sx = plot_x + ((px - min_x) / range_x * plot_w as f64) as f32;
                        let sy = plot_y + plot_h - ((py - min_y) / range_y * plot_h as f64) as f32;

                        // Only draw if within plot area
                        if sx >= plot_x && sx <= plot_x + plot_w && sy >= plot_y && sy <= plot_y + plot_h {
                            self.push_rect(
                                sx - radius,
                                sy - radius,
                                radius * 2.0,
                                radius * 2.0,
                                s.color,
                                radius,
                                0.0,
                                0,
                            );
                        }
                    }
                }
            }
        }

        // Plot border
        self.push_rect(
            plot_x, plot_y, plot_w, plot_h, 0x00000000, 0.0, 1.0, 0xFF4B5563,
        );
    }

    /// Format axis value for display (handles scientific notation for very large/small numbers)
    fn format_axis_value(val: f64) -> String {
        let abs_val = val.abs();
        if abs_val == 0.0 {
            "0".to_string()
        } else if abs_val >= 10000.0 || abs_val < 0.01 {
            // Use scientific notation
            format!("{:.1e}", val)
        } else if abs_val >= 100.0 {
            format!("{:.0}", val)
        } else if abs_val >= 1.0 {
            format!("{:.1}", val)
        } else {
            format!("{:.2}", val)
        }
    }

    fn render_dropdown(
        &mut self,
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        options: &[String],
        selected: usize,
        open: bool,
        placeholder: &str,
        style: &NodeStyle,
        is_hovered: bool,
    ) {
        // Main dropdown button
        let bg_color = style.background_color.unwrap_or(0xFF2D2D2D);
        let bg_color = if is_hovered {
            Self::lighten_color(bg_color, 0.1)
        } else {
            bg_color
        };
        let border_color = if open {
            0xFF3B82F6
        } else {
            style.border_color.unwrap_or(0xFF4B5563)
        };
        let border_width = style.border_width.max(1.0);
        let radius = style.border_radius;

        self.push_rect(x, y, w, h, bg_color, radius, border_width, border_color);

        // Selected text or placeholder
        let text = if selected < options.len() {
            &options[selected]
        } else {
            placeholder
        };
        let text_color = if selected < options.len() {
            style.text_color.unwrap_or(0xFFFFFFFF)
        } else {
            0xFF9CA3AF // Dimmed for placeholder
        };
        let font_size = if style.font_size > 0.0 { style.font_size } else { 14.0 };
        let padding = 12.0;

        self.push_text(
            text,
            x + padding,
            y,
            w - padding * 2.0 - 24.0, // Leave space for arrow
            h,
            font_size,
            text_color,
            TextAlign::Left,
            FontWeight::Regular,
        );

        // Dropdown arrow
        let arrow_x = x + w - 24.0;
        let arrow_y = y + h / 2.0;
        let arrow_color = style.text_color.unwrap_or(0xFFFFFFFF);
        // Draw a simple V shape using two lines
        self.push_line(arrow_x, arrow_y - 3.0, arrow_x + 6.0, arrow_y + 3.0, 2.0, arrow_color);
        self.push_line(arrow_x + 6.0, arrow_y + 3.0, arrow_x + 12.0, arrow_y - 3.0, 2.0, arrow_color);

        // If open, render dropdown list
        if open {
            let item_height = h;
            let list_height = options.len() as f32 * item_height;
            let list_y = y + h;

            // Dropdown list background
            self.push_rect(x, list_y, w, list_height, 0xFF1F2937, radius, border_width, border_color);

            // Render each option
            for (i, option) in options.iter().enumerate() {
                let item_y = list_y + i as f32 * item_height;
                let item_bg = if i == selected {
                    0xFF3B82F6
                } else {
                    0x00000000
                };
                if item_bg != 0 {
                    self.push_rect(x + 2.0, item_y + 2.0, w - 4.0, item_height - 4.0, item_bg, radius - 2.0, 0.0, 0);
                }
                self.push_text(
                    option,
                    x + padding,
                    item_y,
                    w - padding * 2.0,
                    item_height,
                    font_size,
                    0xFFFFFFFF,
                    TextAlign::Left,
                    FontWeight::Regular,
                );
            }
        }
    }

    fn render_tab_header(
        &mut self,
        x: f32,
        y: f32,
        _w: f32,
        h: f32,
        tabs: &[String],
        active: usize,
        style: &NodeStyle,
        _is_hovered: bool,
    ) {
        let bg_color = style.background_color.unwrap_or(0xFF1F2937);
        let font_size = if style.font_size > 0.0 { style.font_size } else { 14.0 };
        let h_padding = 16.0;
        let mut tab_x = x;

        for (i, tab) in tabs.iter().enumerate() {
            let is_active = i == active;

            // Measure tab width
            let tab_width = tab.len() as f32 * font_size * 0.6 + h_padding * 2.0;

            // Tab background
            let tab_bg = if is_active {
                0xFF3B82F6
            } else {
                bg_color
            };
            let radius = if is_active { 4.0 } else { 0.0 };

            self.push_rect(tab_x, y, tab_width, h, tab_bg, radius, 0.0, 0);

            // Tab text
            let text_color = if is_active {
                0xFFFFFFFF
            } else {
                0xFF9CA3AF
            };
            self.push_text(
                tab,
                tab_x,
                y,
                tab_width,
                h,
                font_size,
                text_color,
                TextAlign::Center,
                FontWeight::Regular,
            );

            tab_x += tab_width;
        }

        // Underline for active tab indicator
        // (The active tab already has a colored background)
    }

    fn render_tooltip(
        &mut self,
        x: f32,
        y: f32,
        text: &str,
        style: &NodeStyle,
    ) {
        let bg_color = style.background_color.unwrap_or(0xF0111827);
        let text_color = style.text_color.unwrap_or(0xFFFFFFFF);
        let font_size = if style.font_size > 0.0 { style.font_size } else { 12.0 };
        let padding = 8.0;
        let radius = style.border_radius.max(4.0);

        // Estimate tooltip size
        let text_width = text.len() as f32 * font_size * 0.6;
        let text_height = font_size * 1.4;
        let tooltip_w = text_width + padding * 2.0;
        let tooltip_h = text_height + padding * 2.0;

        // Position tooltip above the element (offset upward)
        let tooltip_x = x;
        let tooltip_y = y - tooltip_h - 4.0;

        // Background with shadow effect
        self.push_rect(tooltip_x + 2.0, tooltip_y + 2.0, tooltip_w, tooltip_h, 0x40000000, radius, 0.0, 0);
        self.push_rect(tooltip_x, tooltip_y, tooltip_w, tooltip_h, bg_color, radius, 0.0, 0);

        // Text
        self.push_text(
            text,
            tooltip_x + padding,
            tooltip_y,
            tooltip_w - padding * 2.0,
            tooltip_h,
            font_size,
            text_color,
            TextAlign::Left,
            FontWeight::Regular,
        );
    }

    fn render_modal_overlay(
        &mut self,
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        title: &str,
        style: &NodeStyle,
    ) {
        // Semi-transparent overlay background (full screen would need special handling)
        // For now, just render the modal box

        let bg_color = style.background_color.unwrap_or(0xFF1F2937);
        let text_color = style.text_color.unwrap_or(0xFFFFFFFF);
        let font_size = if style.font_size > 0.0 { style.font_size } else { 16.0 };
        let radius = style.border_radius.max(8.0);
        let shadow_level = style.shadow_level.max(3);

        // Shadow
        let shadow_offset = shadow_level as f32 * 2.0;
        let shadow_blur = shadow_level as f32 * 4.0;
        self.push_rect(
            x + shadow_offset,
            y + shadow_offset,
            w,
            h,
            0x60000000,
            radius + shadow_blur,
            0.0,
            0,
        );

        // Modal background
        self.push_rect(x, y, w, h, bg_color, radius, 1.0, 0xFF4B5563);

        // Title bar
        let title_height = 48.0;
        self.push_rect(x, y, w, title_height, 0xFF111827, radius, 0.0, 0);

        // Title text
        self.push_text(
            title,
            x + 16.0,
            y,
            w - 64.0, // Leave space for close button
            title_height,
            font_size,
            text_color,
            TextAlign::Left,
            FontWeight::Bold,
        );

        // Close button (X)
        let close_x = x + w - 40.0;
        let close_y = y + 12.0;
        let close_size = 24.0;
        self.push_rect(close_x, close_y, close_size, close_size, 0xFF374151, close_size / 2.0, 0.0, 0);
        // Draw X
        self.push_line(close_x + 6.0, close_y + 6.0, close_x + close_size - 6.0, close_y + close_size - 6.0, 2.0, 0xFFFFFFFF);
        self.push_line(close_x + close_size - 6.0, close_y + 6.0, close_x + 6.0, close_y + close_size - 6.0, 2.0, 0xFFFFFFFF);
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
