# Plan de Arquitectura: Capa de Estrategia de Layout

## Problema Actual

### Impedance Mismatch: CSS vs Egui

| Aspecto | CSS/Tailwind | Egui |
|---------|--------------|------|
| **Modelo** | Restricciones globales (constraint-based) | Pintor inmediato (immediate mode) |
| **Cálculo de altura** | Post-layout: calcula todos los hijos primero | Pre-layout: pregunta "¿cuánto espacio hay?" |
| **`items-center`** | Centra en la línea calculada | Centra en todo el espacio disponible |

### Síntoma Actual
```
flex-row items-center  +  h-full padre
                           ↓
          El hijo se centra en TODA la pantalla
          (no en la "línea" de la fila)
```

### Parche Actual (lines 114-126 en components.rs)
```rust
let safe_to_align_cross = match config.layout_mode {
    LayoutMode::Vertical => true,
    LayoutMode::Horizontal => config.height.is_some(),
};
```

**Problemas:**
1. Pierde funcionalidad (no se puede centrar iconos con texto)
2. Complejidad exponencial con cada nueva propiedad
3. Lógica de layout mezclada con lógica de renderizado

---

## Solución Propuesta: Layout Strategy Layer

### Arquitectura de 3 Capas

```
┌─────────────────────────────────────┐
│  1. StyleConfig (Parser)            │  ← Parse "bg-red-500 items-center"
│     - Solo parsea tokens            │
│     - No toma decisiones            │
└─────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────┐
│  2. LayoutStrategy (NUEVO)          │  ← Toma decisiones inteligentes
│     - Recibe StyleConfig + contexto │
│     - Produce EguiLayoutPlan        │
└─────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────┐
│  3. Components (Renderer)           │  ← Solo ejecuta el plan
│     - Aplica EguiLayoutPlan         │
│     - Sin lógica de decisión        │
└─────────────────────────────────────┘
```

---

## Fase 1: Definir el Contexto de Layout

### Nuevo tipo: `LayoutContext`

```rust
// layout.rs (nuevo archivo)

/// Information about the parent container that affects layout decisions
#[derive(Clone, Debug)]
pub struct LayoutContext {
    /// Available width from parent (None = unconstrained/infinite)
    pub available_width: Option<f32>,
    /// Available height from parent (None = unconstrained/infinite)
    pub available_height: Option<f32>,
    /// Whether this container is the root (CentralPanel)
    pub is_root: bool,
    /// Parent's layout direction (affects cross-axis interpretation)
    pub parent_direction: Option<LayoutMode>,
}

impl LayoutContext {
    pub fn from_ui(ui: &egui::Ui, is_root: bool) -> Self {
        let available = ui.available_size();
        Self {
            available_width: if available.x.is_finite() { Some(available.x) } else { None },
            available_height: if available.y.is_finite() { Some(available.y) } else { None },
            is_root,
            parent_direction: None,
        }
    }

    /// Returns true if cross-axis alignment could cause "explosion"
    pub fn cross_axis_is_unbounded(&self, direction: &LayoutMode) -> bool {
        match direction {
            LayoutMode::Horizontal => self.available_height.is_none(),
            LayoutMode::Vertical => self.available_width.is_none(),
        }
    }
}
```

---

## Fase 2: Definir el Plan de Ejecución

### Nuevo tipo: `EguiLayoutPlan`

```rust
/// The concrete instructions for egui, after strategy resolution
#[derive(Clone, Debug)]
pub struct EguiLayoutPlan {
    /// The base layout to use
    pub layout: egui::Layout,
    /// Whether to wrap content in a sized region first
    pub sizing_strategy: SizingStrategy,
    /// Spacing between items
    pub item_spacing: Option<egui::Vec2>,
}

#[derive(Clone, Debug)]
pub enum SizingStrategy {
    /// Use available space (default egui behavior)
    UseAvailable,
    /// Shrink-wrap to content size, then apply alignment
    ShrinkWrap {
        then_align: Option<egui::Align2>,
    },
    /// Use explicit dimensions
    Fixed {
        width: Option<f32>,
        height: Option<f32>
    },
}
```

---

## Fase 3: El Motor de Estrategia

### Nueva función: `resolve_layout_strategy`

```rust
impl StyleConfig {
    /// Resolves the user's intent into a concrete egui plan
    pub fn resolve_layout(&self, ctx: &LayoutContext) -> EguiLayoutPlan {
        let mut plan = EguiLayoutPlan::default();

        // 1. Base layout direction
        plan.layout = match self.layout_mode {
            LayoutMode::Horizontal => egui::Layout::left_to_right(egui::Align::Min),
            LayoutMode::Vertical => egui::Layout::top_down(egui::Align::Min),
        };

        // 2. Main axis alignment (always safe)
        if let Some(align) = self.main_align {
            plan.layout = plan.layout.with_main_align(align);
        }

        // 3. Cross axis alignment (requires strategy)
        if let Some(cross_align) = self.cross_align {
            plan = self.resolve_cross_alignment(cross_align, ctx, plan);
        }

        // 4. Gap/spacing
        if let Some(gap) = self.gap {
            plan.item_spacing = Some(egui::vec2(gap, gap));
        }

        plan
    }

    fn resolve_cross_alignment(
        &self,
        align: egui::Align,
        ctx: &LayoutContext,
        mut plan: EguiLayoutPlan
    ) -> EguiLayoutPlan {
        // CASE 1: We have explicit dimensions → safe to apply directly
        let has_explicit_cross_dimension = match self.layout_mode {
            LayoutMode::Horizontal => self.height.is_some(),
            LayoutMode::Vertical => self.width.is_some(),
        };

        if has_explicit_cross_dimension {
            plan.layout = plan.layout.with_cross_align(align);
            return plan;
        }

        // CASE 2: Cross-axis is bounded by parent → safe to apply
        if !ctx.cross_axis_is_unbounded(&self.layout_mode) {
            plan.layout = plan.layout.with_cross_align(align);
            return plan;
        }

        // CASE 3: Unbounded cross-axis → use shrink-wrap strategy
        // Instead of centering in infinite space, we:
        // 1. Measure content size
        // 2. Create a region of that size
        // 3. Position that region according to alignment
        plan.sizing_strategy = SizingStrategy::ShrinkWrap {
            then_align: Some(match align {
                egui::Align::Min => egui::Align2::LEFT_TOP,
                egui::Align::Center => egui::Align2::CENTER_CENTER,
                egui::Align::Max => egui::Align2::RIGHT_BOTTOM,
            }),
        };

        plan
    }
}
```

---

## Fase 4: Ejecutor en Components

### Refactorizar `container()`

```rust
pub fn container<F>(style: &Value, children: F)
where
    F: FnOnce(),
{
    if let Some(ui) = bridge::get_ui() {
        let config = StyleConfig::from_value(style);
        let frame = config.to_frame();

        frame.show(ui, |ui| {
            // Build context from current UI state
            let ctx = LayoutContext::from_ui(ui, false);

            // Get the resolved plan
            let plan = config.resolve_layout(&ctx);

            // Execute the plan
            execute_layout_plan(ui, &config, &plan, children);
        });
    }
}

fn execute_layout_plan<F>(
    ui: &mut egui::Ui,
    config: &StyleConfig,
    plan: &EguiLayoutPlan,
    children: F
)
where
    F: FnOnce(),
{
    // Apply explicit dimensions first
    apply_dimensions(ui, config);

    // Apply spacing
    if let Some(spacing) = plan.item_spacing {
        ui.spacing_mut().item_spacing = spacing;
    }

    // Execute based on sizing strategy
    match &plan.sizing_strategy {
        SizingStrategy::UseAvailable => {
            ui.with_layout(plan.layout, |ui| {
                bridge::with_ui_context(ui, children);
            });
        }

        SizingStrategy::ShrinkWrap { then_align } => {
            // Two-pass approach for shrink-wrap
            execute_shrink_wrap(ui, plan, *then_align, children);
        }

        SizingStrategy::Fixed { width, height } => {
            // Apply fixed sizing then layout
            if let Some(w) = width {
                ui.set_min_width(*w);
                ui.set_max_width(*w);
            }
            if let Some(h) = height {
                ui.set_min_height(*h);
                ui.set_max_height(*h);
            }
            ui.with_layout(plan.layout, |ui| {
                bridge::with_ui_context(ui, children);
            });
        }
    }
}

fn execute_shrink_wrap<F>(
    ui: &mut egui::Ui,
    plan: &EguiLayoutPlan,
    align: Option<egui::Align2>,
    children: F,
)
where
    F: FnOnce(),
{
    // For shrink-wrap, we use ui.horizontal/vertical which naturally
    // sizes to content, then position within available space

    match plan.layout.main_dir() {
        egui::Direction::LeftToRight | egui::Direction::RightToLeft => {
            // Horizontal layout - use horizontal() which shrink-wraps
            ui.horizontal(|ui| {
                bridge::with_ui_context(ui, children);
            });
        }
        egui::Direction::TopDown | egui::Direction::BottomUp => {
            // Vertical layout - use vertical() which shrink-wraps
            ui.vertical(|ui| {
                bridge::with_ui_context(ui, children);
            });
        }
    }

    // TODO: Apply alignment offset if needed
    // This is where we'd manually offset based on `align`
}
```

---

## Fase 5: Casos de Uso Soportados

### Caso 1: Row con items centrados verticalmente
```
// Usuario escribe:
box "flex-row items-center gap-2" {
    icon("check")
    label("Confirmado")
}

// Estrategia detecta:
// - Horizontal layout
// - items-center (cross = Center)
// - No explicit height
// - Parent height = unbounded

// Resuelve a:
// SizingStrategy::ShrinkWrap (los items se miden primero)
// Los items quedan alineados entre sí naturalmente
```

### Caso 2: Row en contenedor con altura fija
```
box "h-[50px] flex-row items-center" {
    icon("check")
    label("Confirmado")
}

// Estrategia detecta:
// - Horizontal layout
// - items-center (cross = Center)
// - Explicit height = 50px ✓

// Resuelve a:
// SizingStrategy::Fixed { height: 50 }
// with_cross_align(Center) ← aplicado directamente
```

### Caso 3: Column centrada horizontalmente
```
box "flex-col items-center" {
    label("Título")
    label("Subtítulo")
}

// En vertical, items-center afecta el eje X (width)
// Generalmente width está acotado, así que es seguro aplicar
```

---

## Plan de Implementación

### Paso 1: Crear `layout.rs`
- [ ] Definir `LayoutContext`
- [ ] Definir `EguiLayoutPlan`
- [ ] Definir `SizingStrategy`

### Paso 2: Extender `StyleConfig`
- [ ] Agregar método `resolve_layout(&self, ctx: &LayoutContext) -> EguiLayoutPlan`
- [ ] Implementar lógica de resolución de cross-alignment

### Paso 3: Refactorizar `container()`
- [ ] Eliminar parches if/else actuales
- [ ] Usar el nuevo sistema de plan
- [ ] Implementar ejecutores para cada `SizingStrategy`

### Paso 4: Testing
- [ ] Test: row items-center sin altura (shrink-wrap)
- [ ] Test: row items-center con altura fija (directo)
- [ ] Test: column items-center (generalmente directo)
- [ ] Test: nested layouts

### Paso 5: Documentación
- [ ] Documentar qué clases Tailwind son soportadas
- [ ] Documentar limitaciones conocidas
- [ ] Agregar ejemplos en docs/

---

## Beneficios de Esta Arquitectura

1. **Separación de Responsabilidades**
   - `StyleConfig`: Solo parsea
   - `LayoutStrategy`: Solo decide
   - `Components`: Solo ejecuta

2. **Extensibilidad**
   - Nuevas propiedades CSS → agregar al parser
   - Nuevos casos edge → agregar estrategias
   - Sin modificar el renderizador

3. **Testeabilidad**
   - Podemos testear estrategias sin UI
   - Input: (StyleConfig, LayoutContext)
   - Output: EguiLayoutPlan

4. **Debugging**
   - El plan es inspectable
   - Podemos loggear qué estrategia se eligió

---

## Consideraciones Futuras

### min-w, max-w, min-h, max-h
```rust
pub struct StyleConfig {
    // ...existing...
    pub min_width: Option<f32>,
    pub max_width: Option<f32>,
    pub min_height: Option<f32>,
    pub max_height: Option<f32>,
}
```

### flex-wrap
Requiere estrategia diferente - egui no tiene wrap nativo, habría que simular con múltiples rows.

### justify-between / justify-around
Requiere calcular espaciadores manualmente basándose en el tamaño del contenedor y el contenido.

---

## Próximos Pasos

1. ¿Apruebas esta arquitectura?
2. ¿Hay casos de uso específicos que debamos considerar primero?
3. ¿Quieres que proceda con la implementación paso a paso?
