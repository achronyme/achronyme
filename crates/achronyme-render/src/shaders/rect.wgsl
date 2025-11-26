// Rectangle shader for AUI Engine
// Supports solid colors, rounded corners, and borders

struct VertexInput {
    @location(0) position: vec2<f32>,
    @location(1) uv: vec2<f32>,
    @location(2) color: vec4<f32>,
    @location(3) rect_pos: vec2<f32>,      // Rectangle position (top-left)
    @location(4) rect_size: vec2<f32>,     // Rectangle size
    @location(5) border_radius: f32,       // Corner radius
    @location(6) border_width: f32,        // Border width (0 = no border)
    @location(7) border_color: vec4<f32>,  // Border color
}

struct VertexOutput {
    @builtin(position) clip_position: vec4<f32>,
    @location(0) color: vec4<f32>,
    @location(1) uv: vec2<f32>,
    @location(2) rect_pos: vec2<f32>,
    @location(3) rect_size: vec2<f32>,
    @location(4) border_radius: f32,
    @location(5) border_width: f32,
    @location(6) border_color: vec4<f32>,
    @location(7) pixel_pos: vec2<f32>,
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
    let ndc_y = 1.0 - (in.position.y / uniforms.screen_size.y) * 2.0;  // Flip Y

    out.clip_position = vec4<f32>(ndc_x, ndc_y, 0.0, 1.0);
    out.color = in.color;
    out.uv = in.uv;
    out.rect_pos = in.rect_pos;
    out.rect_size = in.rect_size;
    out.border_radius = in.border_radius;
    out.border_width = in.border_width;
    out.border_color = in.border_color;
    out.pixel_pos = in.position;

    return out;
}

// Signed distance function for rounded rectangle
fn sdf_rounded_rect(p: vec2<f32>, center: vec2<f32>, half_size: vec2<f32>, radius: f32) -> f32 {
    let d = abs(p - center) - half_size + vec2<f32>(radius);
    return length(max(d, vec2<f32>(0.0))) + min(max(d.x, d.y), 0.0) - radius;
}

@fragment
fn fs_main(in: VertexOutput) -> @location(0) vec4<f32> {
    let half_size = in.rect_size * 0.5;
    let center = in.rect_pos + half_size;
    let radius = min(in.border_radius, min(half_size.x, half_size.y));

    // Calculate distance from edge
    let dist = sdf_rounded_rect(in.pixel_pos, center, half_size, radius);

    // Anti-aliasing: smooth transition over ~1 pixel
    let aa_width = 1.0;
    let alpha = 1.0 - smoothstep(-aa_width, aa_width, dist);

    if alpha <= 0.0 {
        discard;
    }

    var final_color = in.color;

    // Handle border
    if in.border_width > 0.0 {
        let inner_dist = sdf_rounded_rect(
            in.pixel_pos,
            center,
            half_size - vec2<f32>(in.border_width),
            max(0.0, radius - in.border_width)
        );

        // Blend between border and fill
        let border_blend = smoothstep(-aa_width, aa_width, inner_dist);
        final_color = mix(in.color, in.border_color, border_blend);
    }

    return vec4<f32>(final_color.rgb, final_color.a * alpha);
}

// Simple solid color shader (for basic rectangles without SDF)
@fragment
fn fs_solid(in: VertexOutput) -> @location(0) vec4<f32> {
    return in.color;
}
