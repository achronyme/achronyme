pub(crate) fn num2bits8_inputs() -> (String, String) {
    (r#"{"in":"13"}"#.to_string(), "in = 13\n".to_string())
}

pub(crate) fn mimcsponge_inputs() -> (String, String) {
    (
        r#"{"ins":["1","2"],"k":"0"}"#.to_string(),
        "ins = [1, 2]\nk = 0\n".to_string(),
    )
}

pub(crate) fn escalarmulany_inputs() -> (String, String) {
    // 254 zero scalar bits, identity point (0, 1).
    let zeros: Vec<&str> = (0..254).map(|_| "\"0\"").collect();
    let json = format!(r#"{{"e":[{}],"p":["0","1"]}}"#, zeros.join(","));
    let mut toml = String::from("p = [0, 1]\ne = [");
    for i in 0..254 {
        if i > 0 {
            toml.push_str(", ");
        }
        toml.push('0');
    }
    toml.push_str("]\n");
    (json, toml)
}

pub(crate) fn sha256_64_inputs() -> (String, String) {
    // 64 zero input bits — exercises the full Sha256(64) compression
    // pipeline. The output digest will be the SHA-256 of all zeros.
    let zeros_json: Vec<&str> = (0..64).map(|_| "\"0\"").collect();
    let json = format!(r#"{{"in":[{}]}}"#, zeros_json.join(","));
    let mut toml = String::from("in = [");
    for i in 0..64 {
        if i > 0 {
            toml.push_str(", ");
        }
        toml.push('0');
    }
    toml.push_str("]\n");
    (json, toml)
}

pub(crate) fn eddsaposeidon_inputs() -> (String, String) {
    // enabled=0 keeps the verify a no-op; the BabyJubjub base point
    // (Base8) keeps intermediate Num2Bits / Edwards-curve wirings
    // valid so the constraint system is satisfiable.
    let ax = "5299619240641551281634865583518297030282874472190772894086521144482721001553";
    let ay = "16950150798460657717958625567821834550301663161624707787222815936182638968203";
    let json = format!(
        r#"{{"enabled":"0","Ax":"{ax}","Ay":"{ay}","S":"1","R8x":"{ax}","R8y":"{ay}","M":"42"}}"#
    );
    let toml = format!(
        "enabled = 0\nAx = \"{ax}\"\nAy = \"{ay}\"\nS = 1\nR8x = \"{ax}\"\nR8y = \"{ay}\"\nM = 42\n"
    );
    (json, toml)
}

pub(crate) fn eddsamimcsponge_inputs() -> (String, String) {
    // Same input shape as EdDSAPoseidon; only the hash backend differs.
    let ax = "5299619240641551281634865583518297030282874472190772894086521144482721001553";
    let ay = "16950150798460657717958625567821834550301663161624707787222815936182638968203";
    let json = format!(
        r#"{{"enabled":"0","Ax":"{ax}","Ay":"{ay}","S":"1","R8x":"{ax}","R8y":"{ay}","M":"42"}}"#
    );
    let toml = format!(
        "enabled = 0\nAx = \"{ax}\"\nAy = \"{ay}\"\nS = 1\nR8x = \"{ax}\"\nR8y = \"{ay}\"\nM = 42\n"
    );
    (json, toml)
}

pub(crate) fn smtprocessor_10_inputs() -> (String, String) {
    // fnc=[0,0]: no-op processor; trivial state transition. `newRoot`
    // is a circom `signal output` — the witness generator computes it,
    // so it MUST NOT appear in `input.json` (snarkjs rejects extra
    // signals as "Too many values"). The TOML side is lenient and
    // ignores the omission either way.
    let zeros_json: Vec<&str> = (0..10).map(|_| "\"0\"").collect();
    let json = format!(
        r#"{{"oldRoot":"0","oldKey":"0","oldValue":"0","isOld0":"0","newKey":"0","newValue":"0","fnc":["0","0"],"siblings":[{}]}}"#,
        zeros_json.join(",")
    );
    let mut toml = String::from(
        "oldRoot = 0\noldKey = 0\noldValue = 0\nisOld0 = 0\nnewKey = 0\nnewValue = 0\nfnc = [0, 0]\nsiblings = [",
    );
    for i in 0..10 {
        if i > 0 {
            toml.push_str(", ");
        }
        toml.push('0');
    }
    toml.push_str("]\n");
    (json, toml)
}

pub(crate) fn smtverifier_10_inputs() -> (String, String) {
    // enabled=0: SMTVerifier becomes a no-op verifier; any input
    // satisfies the constraints. 10 zero siblings cover the full
    // tree depth.
    let zeros_json: Vec<&str> = (0..10).map(|_| "\"0\"").collect();
    let json = format!(
        r#"{{"enabled":"0","fnc":"0","root":"0","oldKey":"0","oldValue":"0","isOld0":"0","key":"0","value":"0","siblings":[{}]}}"#,
        zeros_json.join(",")
    );
    let mut toml = String::from(
        "enabled = 0\nfnc = 0\nroot = 0\noldKey = 0\noldValue = 0\nisOld0 = 0\nkey = 0\nvalue = 0\nsiblings = [",
    );
    for i in 0..10 {
        if i > 0 {
            toml.push_str(", ");
        }
        toml.push('0');
    }
    toml.push_str("]\n");
    (json, toml)
}
