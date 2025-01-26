use crate::msg::{LayerId, PotionWeight, TraitWeight, VariantList};
use crate::storage::may_load;
use cosmwasm_std::{CanonicalAddr, StdResult, Storage};
use cosmwasm_storage::ReadonlyPrefixedStorage;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// storage key for the admins list
pub const ADMINS_KEY: &[u8] = b"admin";
/// storage key for the skull materials
pub const MATERIALS_KEY: &[u8] = b"mater";
/// storage key for the potion ingredients
pub const INGREDIENTS_KEY: &[u8] = b"ingr";
/// storage key for the category names
pub const CATEGORIES_KEY: &[u8] = b"cats";
/// storage key for the staking sets of ingredients
pub const INGRED_SETS_KEY: &[u8] = b"seting";
/// storage key for the StakingState
pub const STAKING_STATE_KEY: &[u8] = b"stkst";
/// storage key for the CrateState
pub const CRATE_STATE_KEY: &[u8] = b"crtst";
/// storage key for the crating base metadata
pub const CRATE_META_KEY: &[u8] = b"metcrt";
/// storage key for the potion base metadata
pub const POTION_META_KEY: &[u8] = b"potmet";
/// storage key for number of ingredients consumed
pub const CONSUMED_KEY: &[u8] = b"cnsm";
/// storage key for the AlchemyState
pub const ALCHEMY_STATE_KEY: &[u8] = b"alcst";
/// storage key for the TransmuteState
pub const TRANSMUTE_STATE_KEY: &[u8] = b"trst";
/// storage key for the potion name keywords
pub const NAME_KEYWORD_KEY: &[u8] = b"nmkw";
/// storage key for the skulls contract info
pub const SKULL_721_KEY: &[u8] = b"sk721";
/// storage key for crate contract infos
pub const CRATES_KEY: &[u8] = b"crat";
/// storage key for potion contract infos
pub const POTION_721_KEY: &[u8] = b"ptn721";
/// storage key for the svg server contract info
pub const SVG_SERVER_KEY: &[u8] = b"srvr";
/// storage key for the variant dependencies
pub const DEPENDENCIES_KEY: &[u8] = b"depend";
/// storage prefix for the user's ingredient inventory
pub const PREFIX_USER_INGR_INVENTORY: &[u8] = b"usinv";
/// storage prefix for the staking set of a user
pub const PREFIX_USER_STAKE: &[u8] = b"usrsk";
/// storage prefix for a skull's staking info
pub const PREFIX_SKULL_STAKE: &[u8] = b"sklstk";
/// storage prefix for variant names
pub const PREFIX_VARIANTS: &[u8] = b"vars";
/// storage prefix for potion rules
pub const PREFIX_POTION_RULES: &[u8] = b"rule";
/// storage prefix for mapping potion names to indices
pub const PREFIX_NAME_2_POTION_IDX: &[u8] = b"idxpt";
/// storage prefix for mapping potion indices to their recipe
pub const PREFIX_POTION_IDX_2_RECIPE: &[u8] = b"recpt";
/// storage prefix for recipes grouped by length
pub const PREFIX_RECIPES_BY_LEN: &[u8] = b"rcpln";
/// storage prefix for mapping recipes to potion names
pub const PREFIX_RECIPE_2_NAME: &[u8] = b"r2nm";
/// storage prefix for whether a potion has been discovered
pub const PREFIX_POTION_FOUND: &[u8] = b"found";
/// storage prefix for potion NFT images and descriptions
pub const PREFIX_POTION_META_ADD: &[u8] = b"desc";
/// storage key for this contract's viewing key with other contracts
pub const MY_VIEWING_KEY: &[u8] = b"myview";
/// prefix for the storage of staking tables
pub const PREFIX_STAKING_TABLE: &[u8] = b"tbstk";
/// prefix for the storage of potion images
pub const PREFIX_POTION_IMAGE: &[u8] = b"imgpt";
/// prefix for pool of unassigned potion image keys
pub const PREFIX_IMAGE_POOL: &[u8] = b"pool";
/// prefix for the storage of revoked permits
pub const PREFIX_REVOKED_PERMITS: &str = "revoke";

/// A trait marking types that have a u16 weight
pub trait Weighted {
    fn weight(&self) -> u16;
}

/// sets of ingredients
#[derive(Serialize, Deserialize)]
pub struct StoredIngrSet {
    /// name of the set
    pub name: String,
    /// list of ingredient indices in this set
    pub list: Vec<u8>,
}

/// ingredient sets and their staking weight
#[derive(Serialize, Deserialize)]
pub struct StoredSetWeight {
    /// idx of the set
    pub set: u8,
    /// weight
    pub weight: u16,
}

/// the latest staker, stake start, and claim time of a skull
#[derive(Serialize, Deserialize)]
pub struct SkullStakeInfo {
    pub addr: CanonicalAddr,
    pub stake: u64,
    pub claim: u64,
}

/// info about crating state
#[derive(Serialize, Deserialize)]
pub struct CrateState {
    /// true if crating is halted
    pub halt: bool,
    /// cnt of crates created
    pub cnt: u128,
}

/// info needed to apply potions
#[derive(Serialize, Deserialize)]
pub struct StoredPotionRules {
    /// randomization weight table for normal skulls
    pub normal_weights: Vec<StoredTraitWeight>,
    /// randomization weight table for jawless
    pub jawless_weights: Vec<StoredTraitWeight>,
    /// randomization weight table for cyclops
    pub cyclops_weights: Vec<StoredTraitWeight>,
    /// the weights to roll the effects of other potions
    pub potion_weights: Vec<PotionWeight>,
    /// skull must have one of the listed traits
    pub required: Vec<StoredVariantList>,
    /// true if this potion rolls a None into non-None
    pub is_add: bool,
    /// true if all potions in potion_weights should be applied
    pub do_all: bool,
    /// true if this potion changes the color but keeps style of a trait
    pub dye_style: bool,
}

/// list of variants grouped by category
#[derive(Serialize, Deserialize)]
pub struct StoredVariantList {
    /// category index
    pub cat: u8,
    /// list of variants in this category
    pub vars: Vec<u8>,
}

impl StoredVariantList {
    /// Returns StdResult<VariantList> from creating a VariantList from a StoredVariantList
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
    ) -> StdResult<VariantList> {
        let cat_big = self.cat as usize;
        // if haven't converted from this category yet
        let these_vars = vars.get_mut(cat_big).unwrap();
        if these_vars.is_empty() {
            let var_store = ReadonlyPrefixedStorage::new(storage, PREFIX_VARIANTS);
            *these_vars =
                may_load::<Vec<String>>(&var_store, &self.cat.to_le_bytes())?.unwrap_or_default();
        }
        Ok(VariantList {
            category: cats[cat_big].clone(),
            variants: self
                .vars
                .iter()
                .map(|u| these_vars[*u as usize].clone())
                .collect::<Vec<String>>(),
        })
    }
}

/// list of layer ids and rolling weights
#[derive(Serialize, Deserialize)]
pub struct StoredTraitWeight {
    /// layer id
    pub layer: StoredLayerId,
    /// rolling weight for this trait
    pub weight: u16,
}

impl Weighted for StoredTraitWeight {
    /// Returns u16
    ///
    /// returns the weight of this trait
    fn weight(&self) -> u16 {
        self.weight
    }
}

impl StoredTraitWeight {
    /// Returns StdResult<TraitWeight> from creating a TraitWeight from a StoredTraitWeight
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
    ) -> StdResult<TraitWeight> {
        Ok(TraitWeight {
            layer: self.layer.to_display(storage, cats, vars)?,
            weight: self.weight,
        })
    }
}

/// global transmutation info
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct TransmuteState {
    /// categories skipped when rolling
    pub skip: Vec<u8>,
    /// None indices
    pub nones: Vec<u8>,
    /// potion indices that can not be used on jawless skulls
    pub jaw_only: Vec<u16>,
    /// StoredLayerId for cyclops
    pub cyclops: StoredLayerId,
    /// StoredLayerId for jawless
    pub jawless: StoredLayerId,
    /// skull category index
    pub skull_idx: u8,
}

/// identifies a layer by indices
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct StoredLayerId {
    /// the layer category
    pub category: u8,
    pub variant: u8,
}

impl StoredLayerId {
    /// Returns StdResult<LayerId> from creating a LayerId from a StoredLayerId
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
    ) -> StdResult<LayerId> {
        let cat_big = self.category as usize;
        // if haven't converted from this category yet
        let these_vars = vars.get_mut(cat_big).unwrap();
        if these_vars.is_empty() {
            let var_store = ReadonlyPrefixedStorage::new(storage, PREFIX_VARIANTS);
            *these_vars = may_load::<Vec<String>>(&var_store, &self.category.to_le_bytes())?
                .unwrap_or_default();
        }

        Ok(LayerId {
            category: cats[cat_big].clone(),
            variant: these_vars[self.variant as usize].clone(),
        })
    }
}

/// info about staking state
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct StakingState {
    /// true if staking is halted
    pub halt: bool,
    /// skull category index
    pub skull_idx: u8,
    /// cooldown period
    pub cooldown: u64,
}

/// info about alchemy state
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct AlchemyState {
    /// true if alchemy is halted
    pub halt: bool,
    /// potions that have been disabled
    pub disabled: Vec<u16>,
    /// number of defined potions
    pub potion_cnt: u16,
    /// number of potions discovered
    pub found_cnt: u16,
    /// total number of potion images
    pub ptn_img_total: u16,
    /// count of unassigned potion images
    pub img_pool_cnt: u16,
}

/// a recipe and the index of the potion it creates
#[derive(Serialize, Deserialize, Clone)]
pub struct RecipeIdx {
    /// the recipe
    pub recipe: Vec<u8>,
    /// index of the potion this creates
    pub idx: u16,
}

/// the image key and optional description postscript for potion nfts
#[derive(Serialize, Deserialize)]
pub struct MetaAdd {
    /// potion image key
    pub image: u16,
    /// optional description postscript
    pub desc: Option<String>,
}
