use crate::contract::BLOCK_SIZE;
use crate::msg::{Dependencies, LayerId, VariantIdxName, ViewerInfo};
use crate::state::StoredLayerId;
use cosmwasm_std::{StdResult, Storage};
use secret_toolkit::utils::Query;
use serde::{Deserialize, Serialize};

/// the svg server's query messages
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerQueryMsg {
    /// return the new image vec resulting from altering the specified layers
    Transmute {
        /// address and viewing key of this alchemy contract
        viewer: ViewerInfo,
        /// current image indices
        current: Vec<u8>,
        /// transmuted layers
        new_layers: Vec<LayerId>,
    },
    /// display the StoredLayerId for jawless and cyclops, and the info about skull materials
    SkullTypePlus {
        /// address and viewing key of the alchemy contract
        viewer: ViewerInfo,
    },
    /// display the category and variant names of a specified category and the variants' indices
    LayerNames {
        /// address and viewing key of the alchemy contract
        viewer: ViewerInfo,
        /// index of the category to display
        idx: u8,
    },
    /// display the dependencies and skipped categories
    ServeAlchemy {
        /// address and viewing key of the alchemy contract
        viewer: ViewerInfo,
    },
}

impl Query for ServerQueryMsg {
    const BLOCK_SIZE: usize = BLOCK_SIZE;
}

/// info about the skull type
#[derive(Deserialize)]
pub struct SkullTypePlus {
    /// cyclops layer
    pub cyclops: StoredLayerId,
    /// jawless layer
    pub jawless: StoredLayerId,
    /// skull category index
    pub skull_idx: u8,
    /// list of all skull materials
    pub skull_variants: Vec<VariantIdxName>,
}

/// wrapper to deserialize SkullTypePlus responses
#[derive(Deserialize)]
pub struct SkullTypePlusWrapper {
    pub skull_type_plus: SkullTypePlus,
}

/// category and variant names and indices
#[derive(Deserialize)]
pub struct LayerNames {
    /// name of the category
    pub category_name: String,
    /// category index specified in the query
    pub category_idx: u8,
    /// variants of this category
    pub variants: Vec<VariantIdxName>,
}

/// wrapper to deserialize LayerNames responses
#[derive(Deserialize)]
pub struct LayerNamesWrapper {
    pub layer_names: LayerNames,
}

/// display the new image vec after transmuting the requested layers
#[derive(Deserialize)]
pub struct Transmute {
    /// new image
    pub image: Vec<u8>,
}

/// wrapper to deserialize Transmute responses
#[derive(Deserialize)]
pub struct TransmuteWrapper {
    pub transmute: Transmute,
}

/// dependencies and skipped categories
#[derive(Deserialize)]
pub struct ServeAlchemyResponse {
    /// categories that are skipped when rolling
    pub skip: Vec<u8>,
    /// variant display dependencies
    pub dependencies: Vec<StoredDependencies>,
}

/// wrapper to deserialize ServeAlchemy responses
#[derive(Deserialize)]
pub struct ServeAlchemyWrapper {
    pub serve_alchemy: ServeAlchemyResponse,
}

/// describes a trait that has multiple layers
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct StoredDependencies {
    /// id of the layer variant that has dependencies
    pub id: StoredLayerId,
    /// the other layers that are correlated to this variant
    pub correlated: Vec<StoredLayerId>,
}

impl StoredDependencies {
    /// Returns StdResult<Dependencies> from creating a Dependencies from a StoredDependencies
    ///
    /// # Arguments
    ///
    /// * `storage` - a reference to the contract storage
    /// * `cats` - category names
    /// * `vars` - variant names
    pub fn to_display(
        &self,
        storage: &dyn Storage,
        cats: &[String],
        vars: &mut [Vec<String>],
    ) -> StdResult<Dependencies> {
        Ok(Dependencies {
            id: self.id.to_display(storage, cats, vars)?,
            correlated: self
                .correlated
                .iter()
                .map(|s| s.to_display(storage, cats, vars))
                .collect::<StdResult<Vec<LayerId>>>()?,
        })
    }
}
