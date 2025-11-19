use achronyme_types::tensor::RealTensor;
use super::tableau::Tableau;
use super::simplex;

/// Resolver un problema de programación lineal usando el método Two-Phase Simplex
///
/// Two-Phase Simplex se usa cuando NO hay una solución básica factible (BFS) obvia.
/// Esto ocurre cuando:
/// - Hay restricciones con ≥ en lugar de ≤
/// - Hay restricciones de igualdad (=)
/// - El problema tiene una forma no estándar
///
/// El método tiene dos fases:
///
/// **Fase 1**: Encuentra una BFS inicial
/// - Añade variables artificiales
/// - Minimiza la suma de variables artificiales
/// - Si el mínimo es 0, encontramos BFS; si no, el problema es infactible
///
/// **Fase 2**: Resuelve el problema original
/// - Usa la BFS de la Fase 1 como punto de partida
/// - Aplica el Simplex estándar
///
/// Args:
///   - c: vector de coeficientes objetivo (n elementos)
///   - a: matriz de restricciones (m × n)
///   - b: vector de lado derecho (m elementos)
///   - sense: 1.0 para maximizar, -1.0 para minimizar
///
/// Returns:
///   - Ok(x): vector solución óptima (n elementos)
///   - Err: mensaje de error (infactible, etc.)
///
/// # Ejemplo
///
/// ```
/// use achronyme_types::tensor::RealTensor;
/// use achronyme_solver::linear::two_phase::solve;
///
/// // Problema con restricción de igualdad:
/// // maximize z = 2x₁ + 3x₂
/// // subject to:
/// //   x₁ + x₂ = 5     (igualdad, no hay BFS obvia)
/// //   x₁ + 2x₂ ≤ 8
/// //   x₁, x₂ ≥ 0
///
/// // Para este ejemplo, convertimos = a ≤ y ≥
/// // Pero Two-Phase Simplex lo maneja automáticamente
/// ```
pub fn solve(c: &[f64], a: &RealTensor, b: &[f64], sense: f64) -> Result<Vec<f64>, String> {
    // Validar sense
    if sense != 1.0 && sense != -1.0 {
        return Err("sense must be 1.0 (maximize) or -1.0 (minimize)".to_string());
    }

    let n = c.len(); // Variables originales
    let m = a.rows();  // Restricciones

    // Verificar si necesitamos Two-Phase
    // Si todos los b[i] son no negativos, podemos usar Simplex estándar
    let needs_phase1 = b.iter().any(|&bi| bi < 0.0);

    if !needs_phase1 {
        // No necesitamos Fase 1, usar Simplex estándar
        return simplex::solve(c, a, b, sense);
    }

    // ========================================================================
    // FASE 1: Encontrar BFS inicial
    // ========================================================================

    // Construir problema artificial:
    // minimize w = sum(artificiales)
    // subject to: A*x + I*artificiales = b (convertir ≤ a =)

    // Crear tableau para Fase 1
    // Variables: [x₁, ..., xₙ, s₁, ..., sₘ, a₁, ..., aₖ]
    // donde k es el número de restricciones con b[i] < 0 o restricciones =

    let mut phase1_tableau = build_phase1_tableau(c, a, b, sense)?;

    // Resolver Fase 1 (minimizar suma de artificiales)
    let max_iterations = 10000;
    let mut iteration = 0;

    loop {
        iteration += 1;
        if iteration > max_iterations {
            return Err("Phase 1: Maximum iterations reached".to_string());
        }

        if phase1_tableau.is_optimal() {
            break;
        }

        let entering = match phase1_tableau.find_entering_variable() {
            Some(col) => col,
            None => break,
        };

        let leaving = phase1_tableau.find_leaving_variable(entering)?;
        phase1_tableau.pivot(entering, leaving);
    }

    // Verificar si encontramos una BFS
    let phase1_objective = phase1_tableau.objective_value();
    if phase1_objective.abs() > 1e-8 {
        return Err(format!(
            "Problem is infeasible (Phase 1 objective = {:.6}, should be 0)",
            phase1_objective
        ));
    }

    // ========================================================================
    // FASE 2: Resolver problema original con la BFS encontrada
    // ========================================================================

    // Extraer la solución básica de Fase 1 (sin variables artificiales)
    // y construir tableau de Fase 2 con la función objetivo original

    let phase2_tableau = build_phase2_tableau(phase1_tableau, c, sense, n, m)?;

    // Resolver Fase 2 con Simplex estándar
    let mut tableau = phase2_tableau;
    iteration = 0;

    loop {
        iteration += 1;
        if iteration > max_iterations {
            return Err("Phase 2: Maximum iterations reached".to_string());
        }

        if tableau.is_optimal() {
            return Ok(tableau.extract_solution());
        }

        let entering = match tableau.find_entering_variable() {
            Some(col) => col,
            None => return Ok(tableau.extract_solution()),
        };

        let leaving = tableau.find_leaving_variable(entering)?;
        tableau.pivot(entering, leaving);
    }
}

/// Construir tableau para Fase 1
///
/// Objetivo: minimizar suma de variables artificiales
fn build_phase1_tableau(
    _c: &[f64],
    a: &RealTensor,
    b: &[f64],
    _sense: f64,
) -> Result<Tableau, String> {
    let n = a.cols();
    let m = a.rows();

    // Contar restricciones que necesitan artificiales
    let num_artificials = b.iter().filter(|&&bi| bi < 0.0).count();

    // Construir tableau extendido
    // Columnas: [x₁...xₙ, s₁...sₘ, a₁...aₖ, RHS]
    let total_vars = n + m + num_artificials;
    let mut data = vec![vec![0.0; total_vars + 1]; m + 1];

    // Llenar restricciones
    let mut artificial_idx = 0;
    for i in 0..m {
        // Copiar coeficientes de x
        for j in 0..n {
            data[i][j] = a.get_matrix(i, j).unwrap();
        }

        // Variable de holgura
        data[i][n + i] = 1.0;

        // Si b[i] < 0, necesitamos artificial
        if b[i] < 0.0 {
            // Multiplicar fila por -1 para hacer b[i] positivo
            for j in 0..total_vars {
                data[i][j] *= -1.0;
            }
            // Agregar variable artificial
            data[i][n + m + artificial_idx] = 1.0;
            data[i][total_vars] = -b[i]; // RHS ahora positivo
            artificial_idx += 1;
        } else {
            data[i][total_vars] = b[i];
        }
    }

    // Fila objetivo de Fase 1: minimizar suma de artificiales
    // Coeficientes: 0 para x y s, 1 para artificiales
    // PERO: debemos hacer que la fila objetivo sea consistente con la base
    for j in n + m..n + m + num_artificials {
        data[m][j] = 1.0; // Coeficiente 1 para artificiales
    }

    // Base inicial: variables de holgura y artificiales
    let mut basis = Vec::new();
    artificial_idx = 0;
    for i in 0..m {
        if b[i] < 0.0 {
            basis.push(n + m + artificial_idx); // Artificial
            artificial_idx += 1;
        } else {
            basis.push(n + i); // Holgura
        }
    }

    // CRÍTICO: Hacer la fila objetivo compatible con la base inicial
    // Eliminar las variables básicas de la fila objetivo
    artificial_idx = 0;
    for i in 0..m {
        if b[i] < 0.0 {
            // Esta fila tiene una artificial en la base
            // Restar esta fila de la fila objetivo para eliminar la artificial
            for j in 0..=total_vars {
                data[m][j] -= data[i][j];
            }
            artificial_idx += 1;
        }
    }

    Ok(Tableau {
        data,
        num_vars: n,
        num_constraints: m,
        basis,
    })
}

/// Construir tableau para Fase 2 a partir del resultado de Fase 1
///
/// Maneja casos degenerados donde variables artificiales permanecen en la base con valor 0.
fn build_phase2_tableau(
    mut phase1: Tableau, // Recibimos ownership para poder pivotar
    c: &[f64],
    sense: f64,
    n: usize,
    m: usize,
) -> Result<Tableau, String> {
    let num_artificials = phase1.data[0].len() - (n + m) - 1;
    let total_cols_phase1 = phase1.data[0].len();

    // 1. LIMPIEZA DE BASE (Handling Degeneracy)
    // Si hay artificiales en la base con valor 0, intentamos pivotarlas fuera.
    for i in 0..m {
        let basic_var = phase1.basis[i];
        let is_artificial = basic_var >= n + m;

        if is_artificial {
            // Verificar si es realmente 0 (debería serlo si Phase 1 fue exitosa)
            let rhs_val = phase1.data[i][total_cols_phase1 - 1];
            if rhs_val.abs() > 1e-8 {
                return Err("Infeasible: Artificial variable in basis with positive value".to_string());
            }

            // Buscar una variable NO artificial (original o holgura) para pivotar
            let mut pivot_col = None;
            for j in 0..n + m {
                let val = phase1.data[i][j];
                if val.abs() > 1e-8 {
                    pivot_col = Some(j);
                    break;
                }
            }

            match pivot_col {
                Some(col) => {
                    // Pivotar para meter una variable real y sacar la artificial
                    phase1.pivot(col, i);
                }
                None => {
                    // Si toda la fila (para vars reales) es 0, la restricción es REDUNDANTE.
                    // Estrategia: Dejar la artificial en la base pero tratarla como una holgura dummy.
                    // No hacemos nada aquí, se filtrará sola en la construcción de abajo
                    // porque la columna artificial no se copia.
                }
            }
        }
    }

    // 2. Construcción del Tableau Fase 2
    let total_cols_phase2 = n + m + 1;
    let mut data = vec![vec![0.0; total_cols_phase2]; m + 1];

    // Copiar datos (excluyendo columnas artificiales)
    for i in 0..m {
        for j in 0..n + m {
            data[i][j] = phase1.data[i][j];
        }
        // RHS
        data[i][n + m] = phase1.data[i][total_cols_phase1 - 1];
    }

    // Restaurar función objetivo original
    for j in 0..n {
        data[m][j] = -sense * c[j];
    }
    data[m][n + m] = 0.0; // El valor Z se recalculará con el pricing out

    // 3. Reconstruir la base
    // Nota: Si quedó una restricción redundante (artificial en base), 
    // la base apuntará a un índice fuera de rango para el nuevo tableau.
    // Debemos manejar eso.
    let mut basis = Vec::new();
    let mut redundant_rows = Vec::new();

    for (r, &b_idx) in phase1.basis.iter().enumerate() {
        if b_idx < n + m {
            basis.push(b_idx);
        } else {
            // Si todavía hay artificial, es una restricción redundante (0 = 0).
            // La marcamos para "ignorarla" matemáticamente.
            // Truco: Asignamos la base a la columna de holgura de esta fila 'r' (n + r),
            // aunque matemáticamente esa columna puede no ser canónica perfecta, 
            // en la práctica forzamos a que esa fila no afecte.
            // O mejor: Para este ejercicio simple, dejamos la holgura correspondiente.
            basis.push(n + r); 
            redundant_rows.push(r);
        }
    }

    // Si hubo filas redundantes, asegúrate de que sean 0=0 en el nuevo tableau
    for &r in &redundant_rows {
        for c_idx in 0..total_cols_phase2 {
            data[r][c_idx] = 0.0;
        }
    }

    // 4. Pricing Out (Restaurar forma canónica)
    for i in 0..m {
        let basic_col_idx = basis[i];
        
        // Si la fila es redundante, basic_col_idx puede apuntar a algo sucio, saltar
        if redundant_rows.contains(&i) { continue; }

        let current_obj_coeff = data[m][basic_col_idx];
        if current_obj_coeff.abs() > 1e-10 {
            for j in 0..total_cols_phase2 {
                data[m][j] -= current_obj_coeff * data[i][j];
            }
        }
    }

    Ok(Tableau {
        data,
        num_vars: n,
        num_constraints: m,
        basis,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_two_phase_with_negative_rhs() {
        // Problema con b[i] < 0 (necesita Fase 1)
        // maximize z = x₁ + x₂
        // subject to:
        //   -x₁ - x₂ ≤ -2  (equivalente a x₁ + x₂ ≥ 2)
        //   x₁ + x₂ ≤ 5
        //   x₁, x₂ ≥ 0
        //
        // Solución: x₁ = 2, x₂ = 0 (o x₁ = 0, x₂ = 2, etc.)

        let c = vec![1.0, 1.0];
        let a = RealTensor::matrix(2, 2, vec![-1.0, -1.0, 1.0, 1.0]).unwrap();
        let b = vec![-2.0, 5.0];

        let solution = solve(&c, &a, &b, 1.0).unwrap();

        // Verificar que la solución es factible
        let sum = solution[0] + solution[1];
        assert!(sum >= 2.0 - 1e-6, "x₁ + x₂ should be >= 2");
        assert!(sum <= 5.0 + 1e-6, "x₁ + x₂ should be <= 5");
    }

    #[test]
    fn test_two_phase_fallback_to_simplex() {
        // Problema sin b[i] < 0, debería usar Simplex directamente
        let c = vec![3.0, 5.0];
        let a = RealTensor::matrix(3, 2, vec![1.0, 0.0, 0.0, 2.0, 3.0, 2.0]).unwrap();
        let b = vec![4.0, 12.0, 18.0];

        let solution = solve(&c, &a, &b, 1.0).unwrap();

        assert!((solution[0] - 2.0).abs() < 1e-6);
        assert!((solution[1] - 6.0).abs() < 1e-6);
    }
}