pub trait LeakageModel {
    fn calculate(&self) -> f32;
}

pub struct HammingWeightLeakage;

impl HammingWeightLeakage {
    pub fn new() -> Self {
        Self {}
    }
}

impl LeakageModel for HammingWeightLeakage {
    fn calculate(&self) -> f32 {
        0.0
    }
}
