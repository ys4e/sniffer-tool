use std::path::Path;
use serde::{Deserialize, Serialize};

#[derive(Default, Clone, Serialize, Deserialize)]
pub enum DisplayType {
    #[default]
    All,
    Whitelist,
    Blacklist
}

impl Into<DisplayType> for String {
    fn into(self) -> DisplayType {
        match self.to_lowercase().as_str() {
            "all" => DisplayType::All,
            "whitelist" => DisplayType::Whitelist,
            "blacklist" => DisplayType::Blacklist,
            _ => {
                warn!("Unknown display type: {}", self);
                DisplayType::All
            }
        }
    }
}

#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserConfig {
    pub display: DisplayType,
    pub whitelist: Vec<String>,
    pub blacklist: Vec<String>
}

impl UserConfig {
    pub fn load() -> Self {
        let path = Path::new("config.json");
        match path.exists() {
            false => {
                let settings: UserConfig = Default::default();
                warn!("No settings file found; using default settings...");
                settings.save();

                settings
            },
            true => {
                let content = std::fs::read_to_string(path)
                    .expect("failed to read settings file");

                serde_json::from_str(&content)
                    .expect("failed to deserialize settings")
            }
        }
    }

    pub fn save(&self) {
        let encoded = serde_json::to_string_pretty(self)
            .expect("failed to serialize settings");

        let path = Path::new("config.json");
        std::fs::write(path, encoded)
            .expect("failed to write settings to file");
    }
}