// Line rendering shader for AUI Engine
// Renders anti-aliased lines using SDF

struct VertexInput {
    @location(0) position: vec2<f32>,      // Vertex position in screen space
    @location(1) line_start: vec2<f32>,    // Line segment start point
    @location(2) line_end: vec2<f32>,      // Line segment end point
    @location(3) color: vec4<f32>,         // Line color
    @location(4) thickness: f32,           // Line thickness
}

struct VertexOutput {
    @builtin(position) clip_position: vec4<f32>,
    @location(0) color: vec4<f32>,
    @location(1) line_start: vec2<f32>,
    @location(2) line_end: vec2<f32>,
    @location(3) pixel_pos: vec2<f32>,
    @location(4) thickness: f32,
}

struct Uniforms {
    screen_size: vec2<f32>,
    _padding: vec2<f32>,
}

@group(0) @binding(0)
var<uniform> uniforms: Uniforms;

@vertex
fn vs_main(in: VertexInput) -> VertexOutput {
    var out: VertexOutput;

    // Convert from pixel coordinates to NDC (-1 to 1)
    let ndc_x = (in.position.x / uniforms.screen_size.x) * 2.0 - 1.0;
    let ndc_y = 1.0 - (in.position.y / uniforms.screen_size.y) * 2.0;

    out.clip_position = vec4<f32>(ndc_x, ndc_y, 0.0, 1.0);
    out.color = in.color;
    out.line_start = in.line_start;
    out.line_end = in.line_end;
    out.pixel_pos = in.position;
    out.thickness = in.thickness;

    return out;
}

// Signed distance to a line segment
fn sdf_line_segment(p: vec2<f32>, a: vec2<f32>, b: vec2<f32>) -> f32 {
    let pa = p - a;
    let ba = b - a;
    let h = clamp(dot(pa, ba) / dot(ba, ba), 0.0, 1.0);
    return length(pa - ba * h);
}

@fragment
fn fs_main(in: VertexOutput) -> @location(0) vec4<f32> {
    // Calculate distance from pixel to line segment
    let dist = sdf_line_segment(in.pixel_pos, in.line_start, in.line_end);

    // Half thickness for the SDF calculation
    let half_thickness = in.thickness * 0.5;

    // Anti-aliasing width (1 pixel)
    let aa_width = 1.0;

    // Calculate alpha based on distance
    let alpha = 1.0 - smoothstep(half_thickness - aa_width, half_thickness + aa_width, dist);

    if alpha <= 0.0 {
        discard;
    }

    return vec4<f32>(in.color.rgb, in.color.a * alpha);
}
