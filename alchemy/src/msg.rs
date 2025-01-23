use crate::contract_info::ContractInfo;
use crate::snip721::Metadata;
use crate::state::{
    AlchemyState, StakingState, StoredLayerId, StoredTraitWeight, StoredVariantList,
    TransmuteState, Weighted, PREFIX_VARIANTS,
};
use crate::storage::may_load;
use cosmwasm_std::{Addr, Binary, StdError, StdResult, Storage, Uint128};
use cosmwasm_storage::ReadonlyPrefixedStorage;
use schemars::JsonSchema;
use secret_toolkit::permit::Permit;
use serde::{Deserialize, Serialize};

/// Instantiation message
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct InstantiateMsg {
    /// optional addresses to add as admins in addition to the instantiator
    pub admins: Option<Vec<String>>,
    /// entropy used for prng seed
    pub entropy: String,
    /// code hash and address of the svg server
    pub svg_server: ContractInfo,
    /// code hash and address of the skulls contract
    pub skulls_contract: ContractInfo,
    /// code hash and address of a crate contract
    pub crate_contract: ContractInfo,
    /// code hash and address of a potion contract
    pub potion_contract: ContractInfo,
    /// number of seconds to earn a staking charge (604800 for prod)
    pub charge_time: u64,
}

/// Handle messages
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    /// try to brew a potion
    BrewPotion {
        /// list of order sensitive potion ingredients
        ingredients: Vec<String>,
    },
    /// claim staking rewards
    ClaimStake {},
    /// set the staking list
    SetStake {
        /// list of skull token ids to stake (up to 5)
        token_ids: Vec<String>,
    },
    /// remove ingredients from a user's inventory to mint an nft containing them
    CrateIngredients { ingredients: Vec<IngredientQty> },
    /* TODO
    /// consume 3 ingredients to rewind the state of a skull if eligible
    Rewind {
        /// the token id of the skull to be rewound
        token_id: String,
        /// the ingredients to consume
        ingredients: Vec<IngredientQty>,
    },
    */
    /// Create a viewing key
    CreateViewingKey { entropy: String },
    /// Set a viewing key
    SetViewingKey {
        key: String,
        // optional padding can be used so message length doesn't betray key length
        padding: Option<String>,
    },
    /// allows an admin to add more admins
    AddAdmins {
        /// list of address to grant admin priveleges
        admins: Vec<String>,
    },
    /// allows an admin to remove admin addresses
    RemoveAdmins {
        /// list of address to revoke admin priveleges from
        admins: Vec<String>,
    },
    /// retrieve category and variant names and indices from the svg server of a specified
    /// category
    GetLayerNames {
        /// category index
        idx: u8,
    },
    /// retrieve dependencies and skipped categories from the svg server
    GetDependencies {},
    /// disable potions
    DisablePotions {
        /// optional list of potion names to disable
        by_name: Option<Vec<String>>,
        /// optional list of potion indices to disable
        by_index: Option<Vec<u16>>,
    },
    /// enable potions
    EnablePotions {
        /// optional list of potion names to enable
        by_name: Option<Vec<String>>,
        /// optional list of potion indices to enable
        by_index: Option<Vec<u16>>,
    },
    /// add ingredients
    AddIngredients { ingredients: Vec<String> },
    /// add potion name keywords
    AddNameKeywords {
        /// keywords for the first position
        first: Vec<String>,
        /// keywords for the second position
        second: Vec<String>,
        /// keywords for the third position
        third: Vec<String>,
        /// keywords for the fourth position
        fourth: Vec<String>,
    },
    /// add potion definitions
    DefinePotions {
        /// new potions
        potion_definitions: Vec<PotionStats>,
    },
    /// create named sets of ingredients for staking tables
    DefineIngredientSets { sets: Vec<IngredientSet> },
    /// create staking tables for specified skull materials
    SetStakingTables { tables: Vec<StakingTable> },
    /// set halt status for staking, crating, and/or alchemy
    SetHaltStatus {
        /// optionally set staking halt status
        staking: Option<bool>,
        /// optionally set alchemy halt status
        alchemy: Option<bool>,
        /// optionally set crating halt status
        crating: Option<bool>,
    },
    /// set charging time for staking
    SetChargeTime {
        /// number of seconds to earn a staking charge (604800 for prod)
        charge_time: u64,
    },
    /// set addresses and code hashes for used contracts
    SetContractInfos {
        /// optional code hash and address of the svg server
        svg_server: Option<ContractInfo>,
        /// optional code hash and address of the skulls contract
        skulls_contract: Option<ContractInfo>,
        /// optional crating contract (can either update the code hash of an existing one or add a new one)
        crate_contract: Option<ContractInfo>,
        /// optional potion contract (can either update the code hash of an existing one or add a new one)
        potion_contract: Option<ContractInfo>,
    },
    /// set the crate nft base metadata
    SetCrateMetadata { public_metadata: Metadata },
    /// set the potion nft base metadata
    SetPotionMetadata { public_metadata: Metadata },
    /// BatchReceiveNft is called when this contract is sent an NFT (potion or crate)
    BatchReceiveNft {
        /// address of the previous owner of the token being sent
        from: String,
        /// list of tokens sent
        token_ids: Vec<String>,
        /// base64 encoded msg to specify the skull the potion should be applied to (if applicable)
        msg: Option<Binary>,
    },
    /// ReceiveNft is only included to maintatin CW721 compliance.  Hopefully everyone uses the
    /// superior BatchReceiveNft process.  ReceiveNft is called when this contract is sent an NFT
    /// (potion or crate)
    ReceiveNft {
        /// address of the previous owner of the token being sent
        sender: String,
        /// the token sent
        token_id: String,
        /// base64 encoded msg to specify the skull the potion should be applied to (if applicable)
        msg: Option<Binary>,
    },
    /// disallow the use of a permit
    RevokePermit {
        /// name of the permit that is no longer valid
        permit_name: String,
    },
}

/// Responses from handle functions
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteAnswer {
    /// response from creating a viewing key
    ViewingKey { key: String },
    /// response from adding/removing admins
    AdminsList {
        /// current admins
        admins: Vec<Addr>,
    },
    /// response from adding ingredients
    AddIngredients {
        /// all known ingredients
        ingredients: Vec<String>,
    },
    /// response from creating named sets of ingredients for staking tables
    DefineIngredientSets {
        /// number of ingredient sets
        count: u8,
    },
    /// response from creating staking tables for specified skull materials
    SetStakingTables { status: String },
    /// response from setting halt status for staking, crating, and/or alchemy
    SetHaltStatus {
        /// true if staking is halted
        staking_is_halted: bool,
        /// true if alchemy is halted
        alchemy_is_halted: bool,
        /// true if crating is halted
        crating_is_halted: bool,
    },
    /// response from setting the crate nft base metadata
    SetCrateMetadata { public_metadata: Metadata },
    /// response from setting the potion nft base metadata
    SetPotionMetadata { public_metadata: Metadata },
    /// response from removing ingredients from a user's inventory to mint an nft containing them
    CrateIngredients {
        updated_inventory: Vec<IngredientQty>,
    },
    /// response from claiming or setting the staking list
    StakeInfo {
        /// charge info of the skulls currently staking
        charge_infos: Vec<ChargeInfo>,
        /// ingredients rewarded in this tx
        rewards: Vec<IngredientQty>,
    },
    /// response from setting charging time for staking
    SetChargeTime {
        /// number of seconds to earn a staking charge (604800 for prod)
        charge_time: u64,
    },
    /// response to setting addresses and code hashes for used contracts
    SetContractInfos {
        /// code hash and address of the svg server
        svg_server: ContractInfo,
        /// code hash and address of the skulls contract
        skulls_contract: ContractInfo,
        /// crate contracts
        crate_contracts: Vec<ContractInfo>,
        /// potion contracts
        potion_contracts: Vec<ContractInfo>,
    },
    /// response from retrieving category and variant names and indices from the svg server of a
    /// specified category
    GetLayerNames {
        /// name of the category
        category_name: String,
        /// category index specified in the query
        category_idx: u8,
        /// variants of this category
        variants: Vec<VariantIdxName>,
    },
    /// response from retrieving dependencies and skipped categories from the svg server
    GetDependencies {
        /// categories that are skipped when rolling
        skip: Vec<u8>,
        /// None indices
        nones: Vec<u8>,
    },
    /// response from disabling/enabling potions
    DisabledPotions {
        /// currently disabled potions
        disabled_potions: Vec<u16>,
    },
    /// response from adding potion name keywords
    AddNameKeywords {
        /// keywords for the first position
        first: Vec<String>,
        /// keywords for the second position
        second: Vec<String>,
        /// keywords for the third position
        third: Vec<String>,
        /// keywords for the fourth position
        fourth: Vec<String>,
    },
    /// response from adding potion definitions
    DefinePotions {
        /// number of potions added
        potions_added: u16,
        // current potion count
        potion_count: u16,
    },
    /// response from trying to brew a potion
    BrewPotion {
        /// if successful, the name of the potion created
        potion_name: Option<String>,
        /// largest number of correct recipe positions for all potions of the
        /// attempted size
        number_correct: u8,
    },
    /// response from revoking a permit
    RevokePermit { status: String },
}

/// Queries
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// displays the halt statuses for staking, crating, and alchemy
    HaltStatuses {},
    /// displays the staking, crating, transmute, and alchemy states
    States {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// displays the common potion and crate metadata
    MintingMetadata {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// displays the keywords used to generate potion names
    NameKeywords {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// lists the admin addresses
    Admins {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// displays the code hashes and addresses of used contracts
    Contracts {},
    /// only displays a user's ingredients inventory (less intensive than MyStaking if you only
    /// need the inventory because it doesn't have to call the skulls contract to verify ownership
    /// of multiple skulls)
    MyIngredients {
        /// optional address and viewing key of a user
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify user identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// displays info about the skulls currently staked by the user and the ingredients they have
    /// in inventory
    MyStaking {
        /// optional address and viewing key of a user
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify user identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// displays if the user is eligible for a first time staking bonus
    UserEligibleForBonus {
        /// optional address and viewing key of a user
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify user identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// displays if the user and token list are eligible for a first time staking bonus
    TokensEligibleForBonus {
        /// optional address and viewing key of a user
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify user identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
        /// list of token ids to check
        token_ids: Vec<String>,
    },
    /// displays the skull materials and indices
    Materials {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// displays the ingredients
    Ingredients {},
    /// displays the ingredient sets
    IngredientSets {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
        /// optional page number to display.  Defaults to 0 (first page) if not provided
        page: Option<u16>,
        /// optional limit to the number of ingredient sets to show.  Defaults to 30 if not specified
        page_size: Option<u16>,
    },
    /// displays the potion rules
    PotionRules {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
        /// optional page number to display.  Defaults to 0 (first page) if not provided
        page: Option<u16>,
        /// optional limit to the number of potions to show.  Defaults to 5 if not specified
        page_size: Option<u16>,
    },
    /// displays the staking table for a specified skull material
    StakingTable {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
        /// optionally display by the material name
        by_name: Option<String>,
        /// optionally display by the material index
        by_index: Option<u8>,
    },
    /// displays the layer names of the specified category index
    LayerNames {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
        /// index of the category to display
        idx: u8,
        /// optional page number to display.  Defaults to 0 (first page) if not provided
        page: Option<u16>,
        /// optional limit to the number of layer names to show.  Defaults to 30 if not specified
        page_size: Option<u16>,
    },
    /// displays the trait variants with dependencies (multiple layers)
    Dependencies {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
        /// optional page number to display.  Defaults to 0 (first page) if not provided
        page: Option<u16>,
        /// optional limit to the number of dependencies to show.  Defaults to 30 if not specified
        page_size: Option<u16>,
    },
}

/// responses to queries
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryAnswer {
    /// displays the common potion and crate metadata
    MintingMetadata {
        /// metadata used when minting crate nfts
        crate_metadata: Metadata,
        /// metadata used when minting potion nfts
        potion_metadata: Metadata,
    },
    /// displays if the user and token list are eligible for a first time staking bonus
    TokensEligibleForBonus {
        /// true if the user is eligible for the first time staking bonus
        user_is_eligible: bool,
        /// eligibility statuses for the requested tokens
        token_eligibility: Vec<EligibilityInfo>,
    },
    /// displays if the user is eligible for a first time staking bonus
    UserEligibleForBonus { is_eligible: bool },
    /// displays the halt statuses for staking, crating, and alchemy
    HaltStatuses {
        /// true if staking has been halted
        staking_is_halted: bool,
        /// true if alchemy has been halted
        alchemy_is_halted: bool,
        /// true if crating has been halted
        crating_is_halted: bool,
    },
    /// response listing the current admins
    Admins { admins: Vec<Addr> },
    /// displays the staking, crating, transmute, and alchemy states
    States {
        staking_state: StakingState,
        alchemy_state: AlchemyState,
        transmute_state: TransmuteState,
        crating_state: DisplayCrateState,
    },
    /// displays the code hashes and addresses of used contracts
    Contracts {
        /// code hash and address of the svg server
        svg_server: ContractInfo,
        /// code hash and address of the skulls contract
        skulls_contract: ContractInfo,
        /// crate contracts
        crate_contracts: Vec<ContractInfo>,
        /// potion contracts
        potion_contracts: Vec<ContractInfo>,
    },
    /// displays the ingredients
    Ingredients { ingredients: Vec<String> },
    /// displays info about the skulls currently staked by the user and the ingredients they have
    /// in inventory
    MyStaking {
        /// true if the user is eligible for the first staking bonus
        first_stake_bonus_available: bool,
        /// charge info of the skulls currently staking
        charge_infos: Vec<ChargeInfo>,
        /// user's ingredient inventory
        inventory: Vec<IngredientQty>,
        /// true if staking is halted (so getting empty arrays for charges)
        staking_is_halted: bool,
    },
    /// only displays a user's ingredients inventory (less intensive than MyStaking if you only
    /// need the inventory because it doesn't have to call the skulls contract to verify ownership
    /// of multiple skulls)
    MyIngredients {
        /// user's ingredient inventory
        inventory: Vec<IngredientQty>,
    },
    /// displays the skull materials and indices
    Materials { materials: Vec<VariantIdxName> },
    /// displays the ingredient sets
    IngredientSets { ingredient_sets: Vec<IngredientSet> },
    /// displays the staking table for a specified skull material
    StakingTable { staking_table: StakingTable },
    /// displays the layer names of the specified category index
    LayerNames {
        /// name of the category
        category_name: String,
        /// category index specified in the query
        category_idx: u8,
        /// number of variants in this category
        count: u8,
        /// variants of this category
        variants: Vec<VariantIdxName>,
    },
    /// displays the trait variants with dependencies (multiple layers)
    Dependencies {
        /// number of dependencies
        count: u16,
        dependencies: Vec<Dependencies>,
    },
    /// display the keywords for generating potion names
    NameKeywords {
        /// keywords for the first position
        first: Vec<String>,
        /// keywords for the second position
        second: Vec<String>,
        /// keywords for the third position
        third: Vec<String>,
        /// keywords for the fourth position
        fourth: Vec<String>,
    },
    /// displays the potion rules
    PotionRules {
        // number of rules
        count: u16,
        // rules
        potion_rules: Vec<DisplayPotionRules>,
    },
}

/// potion definition
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct PotionStats {
    /// randomization weight table for normal skulls
    pub normal_weights: Vec<TraitWeight>,
    /// randomization weight table for jawless
    pub jawless_weights: Vec<TraitWeight>,
    /// randomization weight table for cyclops
    pub cyclops_weights: Vec<TraitWeight>,
    /// the weights to roll the effects of other potions
    pub potion_weights: Vec<PotionWeight>,
    /// skull must have one of the listed traits
    pub required_traits: Vec<VariantList>,
    /// true if this potion rolls a None into non-None
    pub is_addition_potion: bool,
    /// true if all potions in potion_weights should be applied
    pub do_all_listed_potions: bool,
    /// true if this potion changes the color but keeps style of a trait
    pub dye_style: bool,
    /// true if this potion can only be used if the skull has a jaw
    pub jaw_only: bool,
}

/// displayable rules of potion effects
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct DisplayPotionRules {
    /// index of this potion
    pub potion_idx: u16,
    /// randomization weight table for normal skulls
    pub normal_weights: Vec<TraitWeight>,
    /// randomization weight table for jawless
    pub jawless_weights: Vec<TraitWeight>,
    /// randomization weight table for cyclops
    pub cyclops_weights: Vec<TraitWeight>,
    /// the weights to roll the effects of other potions
    pub potion_weights: Vec<PotionWeight>,
    /// skull must have one of the listed traits
    pub required_traits: Vec<VariantList>,
    /// true if this potion rolls a None into non-None
    pub is_addition_potion: bool,
    /// true if all potions in potion_weights should be applied
    pub do_all_listed_potions: bool,
    /// true if this potion changes the color but keeps style of a trait
    pub dye_style: bool,
    /// true if this potion is disabled
    pub is_disabled: bool,
    /// true if this potion can only be used if the skull has a jaw
    pub jaw_only: bool,
    /// true if the recipe has been generated
    pub has_recipe: bool,
}

/// the address and viewing key making an authenticated query request
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct ViewerInfo {
    /// querying address
    pub address: String,
    /// authentication key string
    pub viewing_key: String,
}

/// set of ingredients for the staking tables
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct IngredientSet {
    /// name of the set
    pub name: String,
    /// list of ingredients in this set
    pub members: Vec<String>,
}

/// ingredient sets and their staking weight
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct IngrSetWeight {
    /// name of the set
    pub ingredient_set: String,
    /// weight
    pub weight: u16,
}

/// staking chances of ingredient sets and their weights for a specified skull material
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct StakingTable {
    /// skull material that uses this table
    pub material: String,
    /// ingredient sets and their weights
    pub ingredient_set_weights: Vec<IngrSetWeight>,
}

/// a skull's token id and info about its accrued charges
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct ChargeInfo {
    /// token id fo the skull
    pub token_id: String,
    /// timestamp for beginning of unclaimed charge
    pub charge_start: u64,
    /// whole number of charges accrued since charge_start (game cap at 4)
    pub charges: u8,
}

/// an ingredient and its quantity
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct IngredientQty {
    /// name of the ingredient
    pub ingredient: String,
    /// quantity of this ingredient
    pub quantity: u32,
}

/// displayable info about crating state
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct DisplayCrateState {
    /// true if crating is halted
    pub halt: bool,
    /// number of crates created
    pub cnt: Uint128,
}

/// identifies a layer
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct LayerId {
    /// the layer category name
    pub category: String,
    /// the variant name
    pub variant: String,
}

impl LayerId {
    /// Returns StdResult<StoredLayerId> from creating a StoredLayerId from a LayerId
    ///
    /// # Arguments
    ///
    /// * `storage` - a reference to the contract storage
    /// * `cats` - category names
    /// * `vars` - variant names
    pub fn to_stored(
        &self,
        storage: &dyn Storage,
        cats: &[String],
        vars: &mut [Vec<String>],
    ) -> StdResult<StoredLayerId> {
        let category = cats
            .iter()
            .position(|c| *c == self.category)
            .ok_or_else(|| StdError::generic_err(format!("Category {} not found", self.category)))?
            as u8;
        // if haven't converted from this category yet
        let these_vars = vars.get_mut(category as usize).unwrap();
        if these_vars.is_empty() {
            let var_store = ReadonlyPrefixedStorage::new(storage, PREFIX_VARIANTS);
            *these_vars =
                may_load::<Vec<String>>(&var_store, &category.to_le_bytes())?.unwrap_or_default();
        }

        Ok(StoredLayerId {
            category,
            variant: these_vars
                .iter()
                .position(|v| *v == self.variant)
                .ok_or_else(|| {
                    StdError::generic_err(format!("Variant {} not found", self.variant))
                })? as u8,
        })
    }
}

/// layer id and rolling weight
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct TraitWeight {
    /// layer id
    pub layer: LayerId,
    /// rolling weight for this trait
    pub weight: u16,
}

impl TraitWeight {
    /// Returns StdResult<StoredTraitWeight> from creating a StoredTraitWeight from a TraitWeight
    ///
    /// # Arguments
    ///
    /// * `storage` - a reference to the contract storage
    /// * `cats` - category names
    /// * `vars` - variant names
    pub fn to_stored(
        &self,
        storage: &dyn Storage,
        cats: &[String],
        vars: &mut [Vec<String>],
    ) -> StdResult<StoredTraitWeight> {
        Ok(StoredTraitWeight {
            layer: self.layer.to_stored(storage, cats, vars)?,
            weight: self.weight,
        })
    }
}

/// list of variants grouped by category
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct VariantList {
    /// category
    pub category: String,
    /// list of variants in this category
    pub variants: Vec<String>,
}

impl VariantList {
    /// Returns StdResult<StoredVariantList> from creating a StoredVariantList from a VariantList
    ///
    /// # Arguments
    ///
    /// * `storage` - a reference to the contract storage
    /// * `cats` - category names
    /// * `vars` - variant names
    pub fn to_stored(
        &self,
        storage: &dyn Storage,
        cats: &[String],
        vars: &mut [Vec<String>],
    ) -> StdResult<StoredVariantList> {
        let cat = cats
            .iter()
            .position(|c| *c == self.category)
            .ok_or_else(|| StdError::generic_err(format!("Category {} not found", self.category)))?
            as u8;
        // if haven't converted from this category yet
        let these_vars = vars.get_mut(cat as usize).unwrap();
        if these_vars.is_empty() {
            let var_store = ReadonlyPrefixedStorage::new(storage, PREFIX_VARIANTS);
            *these_vars =
                may_load::<Vec<String>>(&var_store, &cat.to_le_bytes())?.unwrap_or_default();
        }

        Ok(StoredVariantList {
            cat,
            vars: self
                .variants
                .iter()
                .map(|v| {
                    these_vars
                        .iter()
                        .position(|listed| *v == *listed)
                        .ok_or_else(|| StdError::generic_err(format!("Variant {} not found", v)))
                        .map(|u| u as u8)
                })
                .collect::<StdResult<Vec<u8>>>()?,
        })
    }
}

/// first time staking bonus eligibility for a token
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct EligibilityInfo {
    /// token id
    pub token_id: String,
    /// if token is owned by the user, true if the token is eligible for the bonus
    pub is_eligible: Option<bool>,
    /// if token is owned by the user AND it is not eligible, the time it was last claimed
    pub claimed_at: Option<u64>,
}

/// a variant's index and display name
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct VariantIdxName {
    /// index of the variant
    pub idx: u8,
    /// name of the variant
    pub name: String,
}

/// describes a trait that has multiple layers
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct Dependencies {
    /// id of the layer variant that has dependencies
    pub id: LayerId,
    /// the other layers that are correlated to this variant
    pub correlated: Vec<LayerId>,
}

/// a potion index and its rolling weight
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct PotionWeight {
    /// index of the potion
    pub idx: u16,
    /// rolling weight
    pub weight: u16,
}

impl Weighted for PotionWeight {
    /// Returns u16
    ///
    /// returns the weight of this potion
    fn weight(&self) -> u16 {
        self.weight
    }
}
