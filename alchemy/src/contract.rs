use base64::{engine::general_purpose, Engine as _};
use rand_core::RngCore;
use serde::Deserialize;

use cosmwasm_std::{
    entry_point, from_binary, to_binary, Addr, Api, Binary, CanonicalAddr, CosmosMsg, Deps,
    DepsMut, Empty, Env, MessageInfo, Response, StdError, StdResult, Storage, Uint128,
};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
use std::cmp::min;

use secret_toolkit::{
    crypto::{sha_256, ContractPrng},
    permit::{validate, Permit, RevokedPermits},
    utils::{pad_handle_result, pad_query_result, HandleCallback, Query},
    viewing_key::{ViewingKey, ViewingKeyStore},
};

use crate::contract_info::{ContractInfo, StoreContractInfo};
use crate::msg::{
    CategoryRepOverride, ChargeInfo, Dependencies, DisplayCrateState, DisplayPotionRules,
    EligibilityInfo, ExecuteAnswer, ExecuteMsg, IdxImage, IngrSetWeight, IngredientCommonality,
    IngredientQty, IngredientSet, InstantiateMsg, PotionStats, PotionWeight, QueryAnswer, QueryMsg,
    RewindStatus, StakingTable, Testing, TraitWeight, VariantIdxName, VariantList, ViewerInfo,
};
use crate::server_msgs::{
    LayerNamesWrapper, ServeAlchemyWrapper, ServerQueryMsg, StoredDependencies,
};
use crate::snip721::{
    BatchNftDossierWrapper, Burn, ImageInfo, ImageInfoWrapper, Metadata, NftInfoWrapper,
    Snip721HandleMsg, Snip721QueryMsg, Trait,
};
use crate::state::{
    AlchemyState, CrateState, MetaAdd, RecipeGen, RecipeIdx, SkullStakeInfo, StakingState,
    StoredIngrSet, StoredLayerId, StoredPotionRules, StoredSetWeight, StoredTraitWeight,
    StoredVariantList, TransmuteState, Weighted, ADMINS_KEY, ALCHEMY_STATE_KEY, CATEGORIES_KEY,
    CONSUMED_KEY, CRATES_KEY, CRATE_META_KEY, CRATE_STATE_KEY, DEPENDENCIES_KEY, INGREDIENTS_KEY,
    INGRED_SETS_KEY, MATERIALS_KEY, MY_VIEWING_KEY, NAME_KEYWORD_KEY, POTION_721_KEY,
    POTION_META_KEY, PREFIX_IMAGE_POOL, PREFIX_NAME_2_POTION_IDX, PREFIX_POTION_FOUND,
    PREFIX_POTION_IDX_2_RECIPE, PREFIX_POTION_IMAGE, PREFIX_POTION_META_ADD, PREFIX_POTION_RULES,
    PREFIX_RECIPES_BY_LEN, PREFIX_RECIPE_2_NAME, PREFIX_REVOKED_PERMITS, PREFIX_SKULL_STAKE,
    PREFIX_STAKING_TABLE, PREFIX_USER_INGR_INVENTORY, PREFIX_USER_STAKE, PREFIX_VARIANTS,
    RECIPE_GEN_KEY, SKULL_721_KEY, STAKING_STATE_KEY, SVG_SERVER_KEY, TRANSMUTE_STATE_KEY,
};
use crate::storage::{load, may_load, save};

pub const BLOCK_SIZE: usize = 256;
pub const CALC_RARITY_FACTOR: u64 = 300;
pub const USAGE_FACTOR: u64 = 200;
pub const MIN_RECIPE_LEN: i8 = 5;
pub const MAX_RECIPE_LEN: i8 = 9;
pub const RARITY_AVG_THRESHOLD: u8 = 3;
pub const WHEN_THRESHOLD: u8 = 7;
pub const MIN_USAGE_PEN_LIM: u8 = 2;
pub const MAX_USAGE_PEN_LIM: u8 = 8;

////////////////////////////////////// Instantiate ///////////////////////////////////////
/// Returns StdResult<Response>
///
/// Initializes the alchemy contract
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `info` - calling message information MessageInfo
/// * `msg` - InstantiateMsg passed in with the instantiation message
#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let sender_raw = deps.api.addr_canonicalize(info.sender.as_str())?;
    let prng_seed = sha_256(
        general_purpose::STANDARD
            .encode(msg.entropy.as_str())
            .as_bytes(),
    );
    ViewingKey::set_seed(deps.storage, &prng_seed);
    let key = ViewingKey::create(
        deps.storage,
        &info,
        &env,
        info.sender.as_str(),
        msg.entropy.as_ref(),
    );
    save(deps.storage, MY_VIEWING_KEY, &key)?;
    let mut admins = vec![sender_raw];
    if let Some(addrs) = msg.admins {
        add_addrs_to_auth(deps.api, &mut admins, &addrs)?;
    }
    save(deps.storage, ADMINS_KEY, &admins)?;
    let svg_addr = deps
        .api
        .addr_validate(&msg.svg_server.address)
        .and_then(|a| deps.api.addr_canonicalize(a.as_str()))?;
    let svg_raw = StoreContractInfo {
        address: svg_addr,
        code_hash: msg.svg_server.code_hash,
    };
    save(deps.storage, SVG_SERVER_KEY, &svg_raw)?;
    let skull_addr = deps
        .api
        .addr_validate(&msg.skulls_contract.address)
        .and_then(|a| deps.api.addr_canonicalize(a.as_str()))?;
    let skull_raw = StoreContractInfo {
        address: skull_addr,
        code_hash: msg.skulls_contract.code_hash,
    };
    save(deps.storage, SKULL_721_KEY, &skull_raw)?;
    let crate_addr = deps
        .api
        .addr_validate(&msg.crate_contract.address)
        .and_then(|a| deps.api.addr_canonicalize(a.as_str()))?;
    let crate_raw = StoreContractInfo {
        address: crate_addr,
        code_hash: msg.crate_contract.code_hash,
    };
    let mut crates = vec![crate_raw];
    save(deps.storage, CRATES_KEY, &crates)?;
    let potion_addr = deps
        .api
        .addr_validate(&msg.potion_contract.address)
        .and_then(|a| deps.api.addr_canonicalize(a.as_str()))?;
    let potion_raw = StoreContractInfo {
        address: potion_addr,
        code_hash: msg.potion_contract.code_hash,
    };
    let mut potions721 = vec![potion_raw];
    save(deps.storage, POTION_721_KEY, &potions721)?;
    let stk_st = StakingState {
        halt: true,
        skull_idx: 2,
        cooldown: msg.charge_time,
    };
    save(deps.storage, STAKING_STATE_KEY, &stk_st)?;
    let alc_st = AlchemyState {
        halt: true,
        potion_cnt: 0,
        found_cnt: 0,
        disabled: Vec::new(),
        ptn_img_total: 0,
        img_pool_cnt: 0,
    };
    save(deps.storage, ALCHEMY_STATE_KEY, &alc_st)?;
    let trn_st = TransmuteState {
        skip: Vec::new(),
        nones: Vec::new(),
        jaw_only: Vec::new(),
        build_list: Vec::new(),
        cyclops: StoredLayerId {
            category: 5,
            variant: 1,
        },
        jawless: StoredLayerId {
            category: 3,
            variant: 0,
        },
        skull_idx: 2,
    };
    save(deps.storage, TRANSMUTE_STATE_KEY, &trn_st)?;
    let crate_st = CrateState { halt: true, cnt: 0 };
    save(deps.storage, CRATE_STATE_KEY, &crate_st)?;
    let rec_gen = RecipeGen {
        rarities: Vec::new(),
        usage: Vec::new(),
    };
    save(deps.storage, RECIPE_GEN_KEY, &rec_gen)?;
    let messages = vec![
        Snip721HandleMsg::SetViewingKey { key: key.clone() }.to_cosmos_msg(
            svg_raw.code_hash,
            msg.svg_server.address,
            None,
        )?,
        Snip721HandleMsg::SetViewingKey { key }.to_cosmos_msg(
            skull_raw.code_hash,
            msg.skulls_contract.address,
            None,
        )?,
        Snip721HandleMsg::RegisterReceiveNft {
            code_hash: env.contract.code_hash.clone(),
            also_implements_batch_receive_nft: true,
        }
        .to_cosmos_msg(
            crates.swap_remove(0).code_hash,
            msg.crate_contract.address,
            None,
        )?,
        Snip721HandleMsg::RegisterReceiveNft {
            code_hash: env.contract.code_hash,
            also_implements_batch_receive_nft: true,
        }
        .to_cosmos_msg(
            potions721.swap_remove(0).code_hash,
            msg.potion_contract.address,
            None,
        )?,
    ];

    Ok(Response::new().add_messages(messages))
}

///////////////////////////////////// Execute //////////////////////////////////////
/// Returns StdResult<Response>
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `info` - calling message information MessageInfo
/// * `msg` - ExecuteMsg passed in with the execute message
#[entry_point]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    let response = match msg {
        ExecuteMsg::CreateViewingKey { entropy } => try_create_key(deps, &env, &info, &entropy),
        ExecuteMsg::SetViewingKey { key, .. } => try_set_key(deps, &info.sender, key),
        ExecuteMsg::OverrideCategoryRep { overrides } => {
            try_rep_override(deps, &info.sender, overrides)
        }
        ExecuteMsg::UpdateCommonalities { ingredients } => {
            try_update_common(deps, &info.sender, ingredients)
        }
        ExecuteMsg::Rewind {
            token_id,
            ingredients,
        } => try_rewind(deps, env, &info.sender, token_id, ingredients),
        ExecuteMsg::BrewPotion { ingredients } => try_brew(deps, info.sender, ingredients),
        ExecuteMsg::DisablePotions { by_name, by_index } => {
            try_toggle_potions(deps, &info.sender, by_name, by_index, true)
        }
        ExecuteMsg::DefinePotions { potion_definitions } => {
            try_define_potions(deps, &env, &info.sender, potion_definitions)
        }
        ExecuteMsg::AddNameKeywords {
            first,
            second,
            third,
            fourth,
        } => try_add_keywords(deps, &info.sender, first, second, third, fourth),
        ExecuteMsg::AddAdmins { admins } => {
            try_process_auth_list(deps, &info.sender, &admins, true)
        }
        ExecuteMsg::RemoveAdmins { admins } => {
            try_process_auth_list(deps, &info.sender, &admins, false)
        }
        ExecuteMsg::GetLayerNames { idx } => try_get_names(deps, &info.sender, env, idx),
        ExecuteMsg::GetDependencies {} => try_get_deps(deps, &info.sender, env),
        ExecuteMsg::AddIngredients { ingredients } => {
            try_add_ingredients(deps, &info.sender, ingredients)
        }
        ExecuteMsg::SetStakingTables { tables } => try_stake_tbl(deps, &info.sender, tables),
        ExecuteMsg::AddPotionImages { images } => try_add_image(deps, &info.sender, images),
        ExecuteMsg::DeletePotionImages { indices } => try_del_image(deps, &info.sender, indices),
        ExecuteMsg::DefineIngredientSets { sets } => try_set_ingred_set(deps, &info.sender, sets),
        ExecuteMsg::SetHaltStatus {
            staking,
            alchemy,
            crating,
        } => try_set_halt(deps, &info.sender, staking, alchemy, crating),
        ExecuteMsg::SetCrateMetadata { public_metadata } => {
            try_set_meta(deps, &info.sender, public_metadata, true)
        }
        ExecuteMsg::SetPotionMetadata { public_metadata } => {
            try_set_meta(deps, &info.sender, public_metadata, false)
        }
        ExecuteMsg::CrateIngredients { ingredients } => {
            try_mint_crate(deps, info.sender, ingredients)
        }
        ExecuteMsg::SetStake { token_ids } => try_set_stake(deps, env, &info.sender, token_ids),
        ExecuteMsg::ClaimStake {} => try_claim_stake(deps, env, &info.sender),
        ExecuteMsg::SetChargeTime { charge_time } => {
            try_set_charge_time(deps, &info.sender, charge_time)
        }
        ExecuteMsg::SetContractInfos {
            svg_server,
            skulls_contract,
            crate_contract,
            potion_contract,
        } => try_set_contracts(
            deps,
            &info.sender,
            svg_server,
            skulls_contract,
            crate_contract,
            potion_contract,
            env.contract.code_hash,
        ),
        ExecuteMsg::BatchReceiveNft {
            from,
            token_ids,
            msg,
        } => try_batch_receive(deps, env, info.sender, &from, token_ids, msg),
        ExecuteMsg::ReceiveNft {
            sender,
            token_id,
            msg,
        } => try_batch_receive(deps, env, info.sender, &sender, vec![token_id], msg),
        ExecuteMsg::RevokePermit { permit_name } => {
            revoke_permit(deps.storage, &info.sender, &permit_name)
        }
    };
    pad_handle_result(response, BLOCK_SIZE)
}
/// Returns StdResult<Response>
///
/// try to brew a potion
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - the message sender
/// * `recipe` - order sensitive list of ingredients
fn try_brew(deps: DepsMut, sender: Addr, recipe: Vec<String>) -> StdResult<Response> {
    let mut alc_st: AlchemyState = load(deps.storage, ALCHEMY_STATE_KEY)?;
    if alc_st.halt {
        return Err(StdError::generic_err("Alchemy has been halted"));
    }
    let recipe_len = recipe.len() as u8;
    if !(5..=9).contains(&recipe_len) {
        return Err(StdError::generic_err(
            "All recipes are from 5 to 9 ingredients long, inclusive",
        ));
    }
    let mut consumed = may_load::<u128>(deps.storage, CONSUMED_KEY)?.unwrap_or(0);
    // get the ingredient list and the user's inventory
    let user_raw = deps.api.addr_canonicalize(sender.as_str())?;
    let user_key = user_raw.as_slice();
    let (ingredients, mut raw_inv) = get_inventory(deps.storage, user_key)?;
    let mut brew = Vec::new();
    // decrement from inventory and create recipe indices
    for ingr in recipe.iter() {
        let idx = ingredients
            .iter()
            .position(|i| *i == *ingr)
            .ok_or_else(|| StdError::generic_err(format!("{} is not a known ingredient", ingr)))?;
        raw_inv[idx] = raw_inv[idx]
            .checked_sub(1)
            .ok_or_else(|| StdError::generic_err(format!("You do not have enough {}", ingr)))?;
        brew.push(idx as u8);
        // don't see this overflowing in earth's lifetime
        consumed += 1;
    }
    // save consumption count and updated inventory
    save(deps.storage, CONSUMED_KEY, &consumed)?;
    let mut inv_store = PrefixedStorage::new(deps.storage, PREFIX_USER_INGR_INVENTORY);
    save(&mut inv_store, user_key, &raw_inv)?;
    let rc2nm_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_RECIPE_2_NAME);
    let (number_correct, potion_name, messages) =
        if let Some(encoded) = may_load::<Vec<u8>>(&rc2nm_store, brew.as_slice())? {
            // it's a potion
            let idx_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_NAME_2_POTION_IDX);
            // check if this potion has been disabled
            let name_key = encoded.as_slice();
            let ptn_idx = may_load::<u16>(&idx_store, name_key)?
                .ok_or_else(|| StdError::generic_err("Potion name to index storage is corrupt"))?;
            if alc_st.disabled.contains(&ptn_idx) {
                return Err(StdError::generic_err("This potion is currently disabled"));
            }
            let mut found_store = PrefixedStorage::new(deps.storage, PREFIX_POTION_FOUND);
            let idx_key = ptn_idx.to_le_bytes();
            if may_load::<bool>(&found_store, &idx_key)?.is_none() {
                // first time finding this potion
                alc_st.found_cnt += 1;
                save(&mut found_store, &idx_key, &true)?;
                save(deps.storage, ALCHEMY_STATE_KEY, &alc_st)?;
            }
            let mut public_metadata: Metadata = load(deps.storage, POTION_META_KEY)?;
            let potion_name = derive_name(deps.storage, name_key, &mut Vec::new())?;
            public_metadata.extension.name = Some(potion_name.clone());
            let add_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_POTION_META_ADD);
            let meta_add = may_load::<MetaAdd>(&add_store, &idx_key)?
                .ok_or_else(|| StdError::generic_err("MetaAdd storage is corrupt"))?;
            let image_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_POTION_IMAGE);
            let image = may_load::<String>(&image_store, &meta_add.image.to_le_bytes())?
                .ok_or_else(|| StdError::generic_err("Potion image storage is corrupt"))?;
            public_metadata.extension.image_data = Some(image);
            if let Some(addition) = meta_add.desc {
                public_metadata.extension.description = Some(format!(
                    "{}\n\n{}",
                    public_metadata.extension.description.ok_or_else(|| {
                        StdError::generic_err("Potion metadata is missing Description")
                    })?,
                    addition
                ));
            }
            let mut raw_ptns: Vec<StoreContractInfo> = load(deps.storage, POTION_721_KEY)?;
            let ptn_contract = raw_ptns
                .pop()
                .ok_or_else(|| StdError::generic_err("Potion contracts storage is corrupt"))
                .and_then(|s| s.into_humanized(deps.api))?;
            let messages = vec![Snip721HandleMsg::MintNft {
                owner: sender.into_string(),
                public_metadata,
            }
            .to_cosmos_msg(ptn_contract.code_hash, ptn_contract.address, None)?];
            (recipe_len, Some(potion_name), messages)
        } else {
            // not a potion
            let by_len_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_RECIPES_BY_LEN);
            // get all recipes with same length
            let cookbook = may_load::<Vec<RecipeIdx>>(&by_len_store, &recipe_len.to_le_bytes())?
                .unwrap_or_default();
            let mut correct = 0u8;
            // see how close this is to a recipe
            for rcidx in cookbook.iter() {
                if !alc_st.disabled.contains(&rcidx.idx) {
                    // only check potions that have not been disabled
                    let matches = brew
                        .iter()
                        .zip(rcidx.recipe.iter())
                        .filter(|(b, r)| *b == *r)
                        .count() as u8;
                    if matches > correct {
                        correct = matches;
                        if correct >= recipe_len - 1 {
                            // can stop if only 1 wrong
                            break;
                        }
                    }
                }
            }
            (correct, None, Vec::new())
        };
    let mut resp = Response::new();
    if !messages.is_empty() {
        resp = resp.add_messages(messages);
    }

    Ok(resp.set_data(to_binary(&ExecuteAnswer::BrewPotion {
        potion_name,
        number_correct,
    })?))
}

/// Returns StdResult<Response>
///
/// mint a crate nft containing the specified ingredients
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - the message sender
/// * `crate_ingredients` - ingredients that should be crated
fn try_mint_crate(
    deps: DepsMut,
    sender: Addr,
    crate_ingredients: Vec<IngredientQty>,
) -> StdResult<Response> {
    let mut crt_state: CrateState = load(deps.storage, CRATE_STATE_KEY)?;
    if crt_state.halt {
        return Err(StdError::generic_err("Crating has been halted"));
    }
    let user_raw = deps.api.addr_canonicalize(sender.as_str())?;
    let user_key = user_raw.as_slice();
    // get list of all ingredients and the user's inventory
    let (ingredients, mut raw_inv) = get_inventory(deps.storage, user_key)?;
    let ingr_cnt = ingredients.len();
    let mut for_crate: Vec<u32> = vec![0; ingr_cnt];
    // remove the crated ingredients from the user inventory
    for ing_qty in crate_ingredients.into_iter() {
        if let Some(pos) = ingredients.iter().position(|i| *i == ing_qty.ingredient) {
            if raw_inv[pos] < ing_qty.quantity {
                return Err(StdError::generic_err(format!(
                    "You do not have {} {}",
                    ing_qty.quantity, ing_qty.ingredient
                )));
            }
            raw_inv[pos] -= ing_qty.quantity;
            for_crate[pos] += ing_qty.quantity;
        } else {
            return Err(StdError::generic_err(format!(
                "{} is not a known ingredient",
                ing_qty.ingredient
            )));
        }
    }
    let mut inv_store = PrefixedStorage::new(deps.storage, PREFIX_USER_INGR_INVENTORY);
    save(&mut inv_store, user_key, &raw_inv)?;
    let mut public_metadata: Metadata = load(deps.storage, CRATE_META_KEY)?;
    // create traits for the crated ingredients
    let attrs = ingredients
        .iter()
        .zip(for_crate.iter())
        .filter_map(|(ing, qty)| {
            if *qty > 0 {
                Some(Trait {
                    trait_type: ing.clone(),
                    value: qty.to_string(),
                })
            } else {
                None
            }
        })
        .collect::<Vec<Trait>>();
    if attrs.is_empty() {
        return Err(StdError::generic_err(
            "You are trying to make an empty crate",
        ));
    }
    public_metadata.extension.name =
        Some(format!("Mystic Skulls Ingredient Crate #{}", crt_state.cnt));
    crt_state.cnt += 1;
    save(deps.storage, CRATE_STATE_KEY, &crt_state)?;
    public_metadata.extension.attributes = Some(attrs);
    let mut raw_crates: Vec<StoreContractInfo> = load(deps.storage, CRATES_KEY)?;
    let crate_contract = raw_crates
        .pop()
        .ok_or_else(|| StdError::generic_err("Crate contracts storage is corrupt"))
        .and_then(|s| s.into_humanized(deps.api))?;
    let messages = vec![Snip721HandleMsg::MintNft {
        owner: sender.into_string(),
        public_metadata,
    }
    .to_cosmos_msg(crate_contract.code_hash, crate_contract.address, None)?];
    // display what is left in the inventory
    let updated_inventory = ingredients
        .into_iter()
        .zip(raw_inv.into_iter())
        .map(|(ingredient, quantity)| IngredientQty {
            ingredient,
            quantity,
        })
        .collect::<Vec<IngredientQty>>();
    Ok(Response::new().add_messages(messages).set_data(to_binary(
        &ExecuteAnswer::CrateIngredients { updated_inventory },
    )?))
}

/// Returns StdResult<Response>
///
/// claim staking rewards for a user
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `env` - the Env of contract's environment
/// * `sender` - a reference to the message sender
fn try_claim_stake(deps: DepsMut, env: Env, sender: &Addr) -> StdResult<Response> {
    let stk_state: StakingState = load(deps.storage, STAKING_STATE_KEY)?;
    if stk_state.halt {
        return Err(StdError::generic_err("Staking has been halted"));
    }
    let user_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_USER_STAKE);
    let user_raw = deps.api.addr_canonicalize(sender.as_str())?;
    let user_key = user_raw.as_slice();
    // get staking list and only keep the ones the user still owns
    let old_list = may_load::<Vec<String>>(&user_store, user_key)?
        .ok_or_else(|| StdError::generic_err("You have never started staking"))?;
    if old_list.is_empty() {
        return Err(StdError::generic_err("You are not staking any skulls"));
    }
    let (id_images, _, _) = verify_ownership(
        deps.as_ref(),
        sender.as_str(),
        old_list,
        env.contract.address.to_string(),
    )?;
    if id_images.is_empty() {
        return Err(StdError::generic_err(
            "You no longer own any of the skulls you were staking",
        ));
    }
    let materials: Vec<String> = may_load(deps.storage, MATERIALS_KEY)?.unwrap_or_default();
    let mut charges: Vec<u8> = vec![0; materials.len()];
    let mut quantities: Vec<u8> = charges.clone();
    let mut charge_infos: Vec<ChargeInfo> = Vec::new();
    let mut new_list: Vec<String> = Vec::new();
    let now = env.block.time.seconds();
    let mut skull_store = PrefixedStorage::new(deps.storage, PREFIX_SKULL_STAKE);
    for id_img in id_images.into_iter() {
        let id_key = id_img.id.as_bytes();
        let mut stk_inf =
            may_load::<SkullStakeInfo>(&skull_store, id_key)?.unwrap_or(SkullStakeInfo {
                addr: user_raw.clone(),
                stake: now,
                claim: 0,
            });
        // can't claim skulls that are staking with a different user now
        if stk_inf.addr != user_raw {
            continue;
        }
        let time_in_stake = now - stk_inf.stake;
        // tally accrued charges
        let charge_cnt = min(4, time_in_stake / stk_state.cooldown) as u8;
        // if this skull has charge
        if charge_cnt > 0 {
            // tally skull materials
            quantities[id_img.image.natural[stk_state.skull_idx as usize] as usize] += 1;
            charges[id_img.image.natural[stk_state.skull_idx as usize] as usize] += charge_cnt;
            let time_of_maturity = now - (time_in_stake % stk_state.cooldown);
            stk_inf.stake = time_of_maturity;
            stk_inf.claim = time_of_maturity;
            save(&mut skull_store, id_key, &stk_inf)?;
        }
        new_list.push(id_img.id.clone());
        charge_infos.push(ChargeInfo {
            token_id: id_img.id,
            charge_start: stk_inf.stake,
            charges: 0,
        });
    }
    let mut user_store = PrefixedStorage::new(deps.storage, PREFIX_USER_STAKE);
    save(&mut user_store, user_key, &new_list)?;
    let rewards: Vec<IngredientQty> = if charges.iter().any(|i| *i > 0) {
        process_charges(deps.storage, &env, &charges, &quantities, user_key)?
    } else {
        return Err(StdError::generic_err(
            "None of your staked skulls have charges",
        ));
    };

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::StakeInfo {
            charge_infos,
            rewards,
        })?),
    )
}

/// Returns StdResult<Response>
///
/// rewind a skull's image to its last state if possible
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `env` - the Env of contract's environment
/// * `sender` - a reference to the message sender
/// * `token_id` - skull to rewind
/// * `spend` - list of ingredients to consume
fn try_rewind(
    deps: DepsMut,
    env: Env,
    sender: &Addr,
    token_id: String,
    spend: Vec<IngredientQty>,
) -> StdResult<Response> {
    // check if the message sender owns the skull
    let (mut id_images, _, skull_contract) = verify_ownership(
        deps.as_ref(),
        sender.as_str(),
        vec![token_id],
        env.contract.address.to_string(),
    )?;
    let mut id_image = id_images
        .pop()
        .ok_or_else(|| StdError::generic_err("You do not own that skull"))?;
    let user_raw = deps.api.addr_canonicalize(sender.as_str())?;
    let user_key = user_raw.as_slice();
    let mut total = 0u32;
    // get the ingredient list and the user's inventory
    let (ingredients, mut raw_inv) = get_inventory(deps.storage, user_key)?;
    for ing_qty in spend.into_iter() {
        if let Some(pos) = ingredients.iter().position(|i| *i == ing_qty.ingredient) {
            if raw_inv[pos] < ing_qty.quantity {
                return Err(StdError::generic_err(format!(
                    "You do not have {} {}",
                    ing_qty.quantity, ing_qty.ingredient
                )));
            }
            raw_inv[pos] -= ing_qty.quantity;
            total += ing_qty.quantity;
        } else {
            return Err(StdError::generic_err(format!(
                "{} is not a known ingredient",
                ing_qty.ingredient
            )));
        }
    }
    if total != 3 {
        return Err(StdError::generic_err(
            "You must spend exactly 3 ingredients to do a rewind",
        ));
    }
    let mut inv_store = PrefixedStorage::new(deps.storage, PREFIX_USER_INGR_INVENTORY);
    save(&mut inv_store, user_key, &raw_inv)?;
    // check rewind eligibility
    if let Some(err) = can_rewind(&id_image.image) {
        return Err(StdError::generic_err(err));
    }
    let old = id_image.image.current;
    id_image.image.current = id_image.image.previous.clone();
    let trn_st: TransmuteState = load(deps.storage, TRANSMUTE_STATE_KEY)?;
    let cats = may_load::<Vec<String>>(deps.storage, CATEGORIES_KEY)?.unwrap_or_default();
    let zipped_image = id_image.image.current.iter().zip(old.iter());
    let categories_rewound = cats
        .into_iter()
        .enumerate()
        .zip(zipped_image)
        .filter_map(|((i, s), (c, o))| {
            if *c != *o && !trn_st.skip.contains(&(i as u8)) {
                Some(s)
            } else {
                None
            }
        })
        .collect::<Vec<String>>();
    let messages = vec![Snip721HandleMsg::SetImageInfo {
        token_id: id_image.id,
        image_info: id_image.image,
    }
    .to_cosmos_msg(skull_contract.code_hash, skull_contract.address, None)?];
    Ok(Response::new()
        .add_messages(messages)
        .set_data(to_binary(&ExecuteAnswer::Rewind { categories_rewound })?))
}

/// Returns StdResult<Response>
///
/// set the staking inventory for a user
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `env` - the Env of contract's environment
/// * `sender` - a reference to the message sender
/// * `token_ids` - list of skull ids to stake
fn try_set_stake(
    deps: DepsMut,
    env: Env,
    sender: &Addr,
    token_ids: Vec<String>,
) -> StdResult<Response> {
    let stk_state: StakingState = load(deps.storage, STAKING_STATE_KEY)?;
    if stk_state.halt {
        return Err(StdError::generic_err("Staking has been halted"));
    }
    let skull_cnt = token_ids.len();
    // check if staking an appropriate number
    if skull_cnt > 5 {
        return Err(StdError::generic_err("You can only stake up to 5 skulls"));
    }
    // check if sender owns all the skulls they are trying to stake
    let (id_images, not_owned, _) = verify_ownership(
        deps.as_ref(),
        sender.as_str(),
        token_ids,
        env.contract.address.to_string(),
    )?;
    if !not_owned.is_empty() {
        // error out if any or not owned
        let joined = not_owned.join(", ");
        return Err(StdError::generic_err(format!(
            "You do not own skull(s): {}",
            joined
        )));
    }
    let user_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_USER_STAKE);
    let user_raw = deps.api.addr_canonicalize(sender.as_str())?;
    let user_key = user_raw.as_slice();
    let (old_list, do_claim) = if let Some(old) = may_load::<Vec<String>>(&user_store, user_key)? {
        (old, false)
    } else {
        (Vec::new(), true)
    };
    // if they never started claiming, but sent an empty list
    if do_claim && skull_cnt == 0 {
        return Err(StdError::generic_err(
            "Do not waste your First-Stake reward by initializing an empty staking inventory",
        ));
    }
    let materials: Vec<String> = may_load(deps.storage, MATERIALS_KEY)?.unwrap_or_default();
    let mut charges: Vec<u8> = vec![0; materials.len()];
    let mut charge_infos: Vec<ChargeInfo> = Vec::new();
    let mut stk_list: Vec<String> = Vec::new();
    let now = env.block.time.seconds();
    let cutoff = now - stk_state.cooldown;
    let mut skull_store = PrefixedStorage::new(deps.storage, PREFIX_SKULL_STAKE);
    for id_img in id_images.into_iter() {
        let id_key = id_img.id.as_bytes();
        let mut stk_inf =
            may_load::<SkullStakeInfo>(&skull_store, id_key)?.unwrap_or(SkullStakeInfo {
                addr: user_raw.clone(),
                stake: now,
                claim: 0,
            });
        // generate resources if first time user has staked
        // don't allow a first stake reward to be given out for skulls that have been claimed within 1 cooldown
        if do_claim && stk_inf.claim <= cutoff {
            charges[id_img.image.natural[stk_state.skull_idx as usize] as usize] += 1;
            stk_inf.claim = now;
        }
        // if user has not been staking this skull
        if stk_inf.addr != user_raw || !old_list.contains(&id_img.id) {
            stk_inf.addr = user_raw.clone();
            stk_inf.stake = now;
        }
        save(&mut skull_store, id_key, &stk_inf)?;
        stk_list.push(id_img.id.clone());
        charge_infos.push(ChargeInfo {
            token_id: id_img.id,
            charge_start: stk_inf.stake,
            charges: min(4, (now - stk_inf.stake) / stk_state.cooldown) as u8,
        });
    }
    let mut user_store = PrefixedStorage::new(deps.storage, PREFIX_USER_STAKE);
    save(&mut user_store, user_key, &stk_list)?;
    let rewards: Vec<IngredientQty> = if charges.iter().any(|i| *i > 0) {
        process_charges(deps.storage, &env, &charges, &charges, user_key)?
    } else if do_claim {
        return Err(StdError::generic_err("All skulls being staked have not cooled down long enough and are not eligible for First-Stake rewards and would waste this one time offer"));
    } else {
        Vec::new()
    };

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::StakeInfo {
            charge_infos,
            rewards,
        })?),
    )
}

/// Returns StdResult<Response>
///
/// handles receiving NFTs (potion or crate))
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `sender` - the message sender's address
/// * `from` - a reference to the address that owned the NFTs
/// * `token_ids` - list of tokens sent
/// * `msg` - the base64 encoded msg containing the skull to apply the potion to (if applicable)
fn try_batch_receive(
    deps: DepsMut,
    env: Env,
    sender: Addr,
    from: &str,
    token_ids: Vec<String>,
    msg: Option<Binary>,
) -> StdResult<Response> {
    let mut raw_ptn721: Vec<StoreContractInfo> = load(deps.storage, POTION_721_KEY)?;
    let sender_raw = deps.api.addr_canonicalize(sender.as_str())?;
    if let Some(pos) = raw_ptn721.iter().position(|c| c.address == sender_raw) {
        let alc_st: AlchemyState = load(deps.storage, ALCHEMY_STATE_KEY)?;
        if alc_st.halt {
            return Err(StdError::generic_err("Alchemy has been halted"));
        }
        rcv_potion(
            deps,
            env,
            sender.into_string(),
            raw_ptn721.swap_remove(pos).code_hash,
            from,
            token_ids,
            msg,
            &alc_st.disabled,
        )
    } else {
        let mut raw_crates: Vec<StoreContractInfo> = load(deps.storage, CRATES_KEY)?;
        if let Some(pos) = raw_crates.iter().position(|c| c.address == sender_raw) {
            let crt_state: CrateState = load(deps.storage, CRATE_STATE_KEY)?;
            if crt_state.halt {
                return Err(StdError::generic_err("Uncrating has been halted"));
            }
            uncrate(
                deps,
                sender.into_string(),
                raw_crates.swap_remove(pos).code_hash,
                from,
                token_ids,
            )
        } else {
            Err(StdError::generic_err(
                "This may only be called by crate or potion contracts",
            ))
        }
    }
}

/// Returns StdResult<Response>
///
/// add potion naming keywords
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `first` - words to add to the first position
/// * `second` - words to add to the second position
/// * `third` - words to add to the third position
/// * `fourth` - words to add to the fourth position
fn try_add_keywords(
    deps: DepsMut,
    sender: &Addr,
    first: Vec<String>,
    second: Vec<String>,
    third: Vec<String>,
    fourth: Vec<String>,
) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;

    let bundled = vec![first, second, third, fourth];
    let mut keywords = may_load::<Vec<Vec<String>>>(deps.storage, NAME_KEYWORD_KEY)?
        .unwrap_or(vec![Vec::new(); 4]);

    for (i, list) in bundled.into_iter().enumerate() {
        let keylist = keywords
            .get_mut(i)
            .ok_or_else(|| StdError::generic_err("Can't happen with what's coded above"))?;
        for word in list.into_iter() {
            if !keylist.contains(&word) {
                keylist.push(word);
            }
        }
    }
    save(deps.storage, NAME_KEYWORD_KEY, &keywords)?;

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::AddNameKeywords {
            fourth: keywords.pop().unwrap(),
            third: keywords.pop().unwrap(),
            second: keywords.pop().unwrap(),
            first: keywords.pop().unwrap(),
        })?),
    )
}

/// Returns StdResult<Response>
///
/// define new potions
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `env` - a reference to the Env of contract's environment
/// * `sender` - a reference to the message sender
/// * `potion_definitions` - list of potion definitions
fn try_define_potions(
    deps: DepsMut,
    env: &Env,
    sender: &Addr,
    potion_definitions: Vec<PotionStats>,
) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;

    let mut alc_st: AlchemyState = load(deps.storage, ALCHEMY_STATE_KEY)?;
    let mut trn_st: TransmuteState = load(deps.storage, TRANSMUTE_STATE_KEY)?;
    let mut prng = ContractPrng::from_env(env);
    let keywords =
        may_load::<Vec<Vec<String>>>(deps.storage, NAME_KEYWORD_KEY)?.ok_or_else(|| {
            StdError::generic_err("Keywords for potion name generation has not been added yet")
        })?;
    let word_cnts = keywords
        .iter()
        .map(|l| l.len() as u64)
        .collect::<Vec<u64>>();
    let cats = may_load::<Vec<String>>(deps.storage, CATEGORIES_KEY)?.unwrap_or_default();
    let cat_cnt = cats.len();
    let mut vars = vec![Vec::new(); cat_cnt];
    let old_ptn_cnt = alc_st.potion_cnt;
    let mut rec_gen = may_load::<RecipeGen>(deps.storage, RECIPE_GEN_KEY)?
        .ok_or_else(|| StdError::generic_err("RecipeGen storage is corrupt"))?;
    // weights to randomly adjust the recipe length from input complexity
    let len_adj = vec![
        LengthAdj { adj: 0, weight: 4 },
        LengthAdj { adj: 1, weight: 3 },
        LengthAdj { adj: -1, weight: 3 },
        LengthAdj { adj: 2, weight: 1 },
        LengthAdj { adj: -2, weight: 1 },
    ];
    for potion in potion_definitions.into_iter() {
        // generate a unique encoded potion name
        let mut idx_store = PrefixedStorage::new(deps.storage, PREFIX_NAME_2_POTION_IDX);
        let mut encoded: Vec<u8> = Vec::new();
        let mut not_unique = true;
        while not_unique {
            encoded = word_cnts
                .iter()
                .map(|u| (prng.next_u64() % u) as u8)
                .collect::<Vec<u8>>();
            not_unique = may_load::<u16>(&idx_store, encoded.as_slice())?.is_some();
        }
        save(&mut idx_store, encoded.as_slice(), &alc_st.potion_cnt)?;
        // pick a random potion image
        if alc_st.img_pool_cnt == 0 {
            return Err(StdError::generic_err(
                "There are no unassigned potion images",
            ));
        }
        let pool_idx = (prng.next_u64() % alc_st.img_pool_cnt as u64) as u16;
        let pool_key = pool_idx.to_le_bytes();
        alc_st.img_pool_cnt -= 1;
        let mut pool_store = PrefixedStorage::new(deps.storage, PREFIX_IMAGE_POOL);
        let image = may_load::<u16>(&pool_store, &pool_key)?
            .ok_or_else(|| StdError::generic_err("Potion image pool keys are corrupt"))?;
        // if picked the last key, we're done
        if pool_idx != alc_st.img_pool_cnt {
            let last = may_load::<u16>(&pool_store, &alc_st.img_pool_cnt.to_le_bytes())?
                .ok_or_else(|| StdError::generic_err("Potion image pool keys are corrupt"))?;
            save(&mut pool_store, &pool_key, &last)?;
        }
        let rule = StoredPotionRules {
            normal_weights: potion
                .normal_weights
                .iter()
                .map(|w| w.to_stored(deps.storage, &cats, &mut vars))
                .collect::<StdResult<Vec<StoredTraitWeight>>>()?,
            jawless_weights: potion
                .jawless_weights
                .iter()
                .map(|w| w.to_stored(deps.storage, &cats, &mut vars))
                .collect::<StdResult<Vec<StoredTraitWeight>>>()?,
            cyclops_weights: potion
                .cyclops_weights
                .iter()
                .map(|w| w.to_stored(deps.storage, &cats, &mut vars))
                .collect::<StdResult<Vec<StoredTraitWeight>>>()?,
            potion_weights: potion.potion_weights,
            required: potion
                .required_traits
                .iter()
                .map(|t| t.to_stored(deps.storage, &cats, &mut vars))
                .collect::<StdResult<Vec<StoredVariantList>>>()?,
            is_add: potion.is_addition_potion,
            do_all: potion.do_all_listed_potions,
            dye_style: potion.dye_style,
            build_list: potion.build_list,
            cat_rep: potion.category_rep,
            complex: potion.complexity,
            rare: potion.commonality,
        };
        // shouldn't ever be possible to already have this idx in jaw_only, but in case some
        // later code migration has a buggy side effect...
        if potion.jaw_only && !trn_st.jaw_only.contains(&alc_st.potion_cnt) {
            trn_st.jaw_only.push(alc_st.potion_cnt);
        }
        let idx_key = alc_st.potion_cnt.to_le_bytes();
        let mut rul_store = PrefixedStorage::new(deps.storage, PREFIX_POTION_RULES);
        // if this potion is one to use for full rerolls or addition
        if rule.cat_rep {
            change_cat_rep(
                &mut rul_store,
                &mut trn_st.build_list,
                rule.normal_weights[0].layer.category as usize,
                alc_st.potion_cnt,
                false,
            )?;
        }
        save(&mut rul_store, &idx_key, &rule)?;
        // save the image key and optional description postscript
        let meta_add = MetaAdd {
            image,
            desc: potion.description_postscript,
        };
        let mut add_store = PrefixedStorage::new(deps.storage, PREFIX_POTION_META_ADD);
        save(&mut add_store, &idx_key, &meta_add)?;
        // generate the recipe
        let mut rcp2nm_store = PrefixedStorage::new(deps.storage, PREFIX_RECIPE_2_NAME);
        let recipe = gen_recipe(
            &mut rcp2nm_store,
            &len_adj,
            &mut rec_gen,
            &mut prng,
            &encoded,
            potion.commonality,
            potion.complexity as i8,
        )?;
        let recipe_len = recipe.len() as u8;
        // map the potion idx to the recipe
        let mut p2r_store = PrefixedStorage::new(deps.storage, PREFIX_POTION_IDX_2_RECIPE);
        save(&mut p2r_store, &idx_key, &recipe)?;
        // add to recipes grouped by length
        let rec_idx = RecipeIdx {
            recipe,
            idx: alc_st.potion_cnt,
        };
        let mut by_len_store = PrefixedStorage::new(deps.storage, PREFIX_RECIPES_BY_LEN);
        let by_len_key = recipe_len.to_le_bytes();
        // get all recipes with same length
        let mut cookbook =
            may_load::<Vec<RecipeIdx>>(&by_len_store, &by_len_key)?.unwrap_or_default();
        cookbook.push(rec_idx);
        save(&mut by_len_store, &by_len_key, &cookbook)?;
        alc_st.potion_cnt = alc_st.potion_cnt.checked_add(1).ok_or_else(|| {
            StdError::generic_err("Reached implementation limit for potion definition")
        })?;
    }

    save(deps.storage, ALCHEMY_STATE_KEY, &alc_st)?;
    save(deps.storage, TRANSMUTE_STATE_KEY, &trn_st)?;

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::DefinePotions {
            potions_added: alc_st.potion_cnt - old_ptn_cnt,
            potion_count: alc_st.potion_cnt,
        })?),
    )
}

/// Returns StdResult<Response>
///
/// disable/enable potions
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `by_name` - optional list of potion names to set
/// * `by_index` - optional list of potion indices to set
/// * `turn_off` - true if the potions are being disabled
fn try_toggle_potions(
    deps: DepsMut,
    sender: &Addr,
    by_name: Option<Vec<String>>,
    by_index: Option<Vec<u16>>,
    turn_off: bool,
) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;

    let names = by_name.unwrap_or_default();
    let mut indices = by_index.unwrap_or_default();
    let mut alc_st: AlchemyState = load(deps.storage, ALCHEMY_STATE_KEY)?;
    let mut trn_st: TransmuteState = load(deps.storage, TRANSMUTE_STATE_KEY)?;
    let idx_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_NAME_2_POTION_IDX);
    // convert the names into indices and combine the lists
    let mut keywords = Vec::new();
    let mut converted = names
        .iter()
        .map(|n| {
            encode_name(deps.storage, n, &mut keywords)
                .and_then(|code| may_load::<u16>(&idx_store, code.as_slice()))
                .and_then(|o| {
                    o.ok_or_else(|| StdError::generic_err(format!("Unknown potion name {}", n)))
                })
        })
        .collect::<StdResult<Vec<u16>>>()?;
    indices.append(&mut converted);

    if turn_off {
        // disabling
        for ptn in indices.iter() {
            if *ptn >= alc_st.potion_cnt {
                return Err(StdError::generic_err(format!(
                    "{} is not a valid potion index",
                    ptn
                )));
            }
            // add the potion to the disabled list if it's not already there
            if !alc_st.disabled.contains(ptn) {
                alc_st.disabled.push(*ptn);
            }
            // check if this potion is a category representative and clear the rep if so
            if let Some(cat_idx) = trn_st.build_list.iter().position(|p| *p == *ptn) {
                let mut rul_store = PrefixedStorage::new(deps.storage, PREFIX_POTION_RULES);
                change_cat_rep(
                    &mut rul_store,
                    &mut trn_st.build_list,
                    cat_idx,
                    u16::MAX,
                    false,
                )?;
            }
            // remove the recipe from the discovery list
            let p2r_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_POTION_IDX_2_RECIPE);
            if let Some(recipe) = may_load::<Vec<u8>>(&p2r_store, &ptn.to_le_bytes())? {
                let recipe_len = recipe.len() as u8;
                let mut by_len_store = PrefixedStorage::new(deps.storage, PREFIX_RECIPES_BY_LEN);
                let by_len_key = recipe_len.to_le_bytes();
                // get all recipes with same length
                let mut cookbook =
                    may_load::<Vec<RecipeIdx>>(&by_len_store, &by_len_key)?.unwrap_or_default();
                if let Some(fnd) = cookbook.iter().position(|r| r.recipe == recipe) {
                    cookbook.swap_remove(fnd);
                    save(&mut by_len_store, &by_len_key, &cookbook)?;
                }
            }
        }
        // remove disabled potions from the jaw_only list
        trn_st.jaw_only.retain(|p| !indices.contains(p));
    } else {
        // enabling
        alc_st.disabled.retain(|p| !indices.contains(p));
    }
    // save the disabled list
    save(deps.storage, ALCHEMY_STATE_KEY, &alc_st)?;
    // save the build and jaw only list
    save(deps.storage, TRANSMUTE_STATE_KEY, &trn_st)?;

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::DisabledPotions {
            disabled_potions: alc_st.disabled,
        })?),
    )
}

/// Returns StdResult<Response>
///
/// set code hashes and addresses of used contracts
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `new_svg_server` - optional code hash and address of the svg server
/// * `new_skulls_contract` - optional code hash and address of the skulls contract
/// * `new_crate_contract` - optional code hash and address of a crating contract (can either update the code
///                     hash of an existing one or add a new one)
/// * `new_potion_contract` - optional code hash and address of a potion contract (can either update the code
///                     hash of an existing one or add a new one)
/// * `code_hash` - code hash of this contract
fn try_set_contracts(
    deps: DepsMut,
    sender: &Addr,
    new_svg_server: Option<ContractInfo>,
    new_skulls_contract: Option<ContractInfo>,
    new_crate_contract: Option<ContractInfo>,
    new_potion_contract: Option<ContractInfo>,
    code_hash: String,
) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;

    let mut messages: Vec<CosmosMsg> = Vec::new();
    let key: String = load(deps.storage, MY_VIEWING_KEY)?;

    let svg_server = if let Some(svg) = new_svg_server {
        let raw = svg.get_store(deps.api)?;
        messages.push(
            Snip721HandleMsg::SetViewingKey { key: key.clone() }.to_cosmos_msg(
                svg.code_hash.clone(),
                svg.address.clone(),
                None,
            )?,
        );
        save(deps.storage, SVG_SERVER_KEY, &raw)?;
        svg
    } else {
        load::<StoreContractInfo>(deps.storage, SVG_SERVER_KEY)
            .and_then(|s| s.into_humanized(deps.api))?
    };
    let skulls_contract = if let Some(skl) = new_skulls_contract {
        let raw = skl.get_store(deps.api)?;
        messages.push(Snip721HandleMsg::SetViewingKey { key }.to_cosmos_msg(
            skl.code_hash.clone(),
            skl.address.clone(),
            None,
        )?);
        save(deps.storage, SKULL_721_KEY, &raw)?;
        skl
    } else {
        load::<StoreContractInfo>(deps.storage, SKULL_721_KEY)
            .and_then(|s| s.into_humanized(deps.api))?
    };
    let mut raw_crates: Vec<StoreContractInfo> = load(deps.storage, CRATES_KEY)?;
    if let Some(crt) = new_crate_contract {
        let raw = crt.get_store(deps.api)?;
        if let Some(old) = raw_crates.iter_mut().find(|c| c.address == raw.address) {
            old.code_hash = raw.code_hash;
        } else {
            raw_crates.push(raw);
        }
        save(deps.storage, CRATES_KEY, &raw_crates)?;
        messages.push(
            Snip721HandleMsg::RegisterReceiveNft {
                code_hash: code_hash.clone(),
                also_implements_batch_receive_nft: true,
            }
            .to_cosmos_msg(crt.code_hash, crt.address, None)?,
        );
    }
    let mut raw_potions: Vec<StoreContractInfo> = load(deps.storage, POTION_721_KEY)?;
    if let Some(ptn) = new_potion_contract {
        let raw = ptn.get_store(deps.api)?;
        if let Some(old) = raw_potions.iter_mut().find(|c| c.address == raw.address) {
            old.code_hash = raw.code_hash;
        } else {
            raw_potions.push(raw);
        }
        save(deps.storage, POTION_721_KEY, &raw_potions)?;
        messages.push(
            Snip721HandleMsg::RegisterReceiveNft {
                code_hash,
                also_implements_batch_receive_nft: true,
            }
            .to_cosmos_msg(ptn.code_hash, ptn.address, None)?,
        );
    }
    let mut resp = Response::new();
    if !messages.is_empty() {
        resp = resp.add_messages(messages);
    }
    Ok(resp.set_data(to_binary(&ExecuteAnswer::SetContractInfos {
        svg_server,
        skulls_contract,
        crate_contracts: raw_crates
            .into_iter()
            .map(|s| s.into_humanized(deps.api))
            .collect::<StdResult<Vec<ContractInfo>>>()?,
        potion_contracts: raw_potions
            .into_iter()
            .map(|s| s.into_humanized(deps.api))
            .collect::<StdResult<Vec<ContractInfo>>>()?,
    })?))
}

/// Returns StdResult<Response>
///
/// set the staking charge time
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `charge_time` - staking charge time in seconds
fn try_set_charge_time(deps: DepsMut, sender: &Addr, charge_time: u64) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;

    let mut stk_st: StakingState = load(deps.storage, STAKING_STATE_KEY)?;
    if stk_st.cooldown != charge_time {
        stk_st.cooldown = charge_time;
        save(deps.storage, STAKING_STATE_KEY, &stk_st)?;
    }

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::SetChargeTime {
            charge_time: stk_st.cooldown,
        })?),
    )
}

/// Returns StdResult<Response>
///
/// set the halt status of staking, crating, and/or alchemy
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `staking` - optionally set staking halt status
/// * `alchemy` - optionally set alchemy halt status
/// * `crating` - optionally set crating halt status
fn try_set_halt(
    deps: DepsMut,
    sender: &Addr,
    staking: Option<bool>,
    alchemy: Option<bool>,
    crating: Option<bool>,
) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;

    let mut stk_st: StakingState = load(deps.storage, STAKING_STATE_KEY)?;
    let mut alc_st: AlchemyState = load(deps.storage, ALCHEMY_STATE_KEY)?;
    let mut crt_st: CrateState = load(deps.storage, CRATE_STATE_KEY)?;
    // if setting staking halt status
    if let Some(stk) = staking {
        // if it would change
        if stk_st.halt != stk {
            stk_st.halt = stk;
            // if enabling staking
            if !stk_st.halt {
                let materials: Vec<String> =
                    may_load(deps.storage, MATERIALS_KEY)?.unwrap_or_default();
                if materials.is_empty() {
                    return Err(StdError::generic_err("Skull materials are undefined"));
                }
                // check if all materials have a staking table
                let tbl_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_STAKING_TABLE);
                for (i, mat) in materials.into_iter().enumerate() {
                    let i_sml = i as u8;
                    if may_load::<Vec<StoredSetWeight>>(&tbl_store, &i_sml.to_le_bytes())?.is_none()
                    {
                        return Err(StdError::generic_err(format!(
                            "{} staking table has not been defined",
                            mat
                        )));
                    }
                }
            }
            save(deps.storage, STAKING_STATE_KEY, &stk_st)?;
        }
    }
    // if setting alchemy halt status
    if let Some(alc) = alchemy {
        // if it would change
        if alc_st.halt != alc {
            alc_st.halt = alc;
            // if enabling alchemy
            if !alc_st.halt {
                // verify that we have potion nft metadata
                if may_load::<Metadata>(deps.storage, POTION_META_KEY)?.is_none() {
                    return Err(StdError::generic_err(
                        "Potion metadata has not been added yet",
                    ));
                }
            }
            save(deps.storage, ALCHEMY_STATE_KEY, &alc_st)?;
        }
    }
    // if setting crating state
    if let Some(crt) = crating {
        // if it would change
        if crt_st.halt != crt {
            crt_st.halt = crt;
            // if enabling crating
            if !crt_st.halt {
                // verify that we have crate nft metadata
                if may_load::<Metadata>(deps.storage, CRATE_META_KEY)?.is_none() {
                    return Err(StdError::generic_err(
                        "Crate metadata has not been added yet",
                    ));
                }
            }
            save(deps.storage, CRATE_STATE_KEY, &crt_st)?;
        }
    }

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::SetHaltStatus {
            staking_is_halted: stk_st.halt,
            alchemy_is_halted: alc_st.halt,
            crating_is_halted: crt_st.halt,
        })?),
    )
}

/// Returns StdResult<Response>
///
/// set the base metadata for crate and potion nfts
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `public_metadata` - base metadata for crate/potion nfts
/// * `for_crate` - true if this metadata is for crate nfts
fn try_set_meta(
    deps: DepsMut,
    sender: &Addr,
    public_metadata: Metadata,
    for_crate: bool,
) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;

    let resp = if for_crate {
        save(deps.storage, CRATE_META_KEY, &public_metadata)?;
        ExecuteAnswer::SetCrateMetadata { public_metadata }
    } else {
        save(deps.storage, POTION_META_KEY, &public_metadata)?;
        ExecuteAnswer::SetPotionMetadata { public_metadata }
    };

    Ok(Response::new().set_data(to_binary(&resp)?))
}

/// Returns StdResult<Response>
///
/// update the commonality scores of specified ingredients
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `updates` - new IngredientCommonality values to use
fn try_update_common(
    deps: DepsMut,
    sender: &Addr,
    updates: Vec<IngredientCommonality>,
) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;
    let ingredients: Vec<String> = may_load(deps.storage, INGREDIENTS_KEY)?.unwrap_or_default();
    let mut rec_gen = may_load::<RecipeGen>(deps.storage, RECIPE_GEN_KEY)?
        .ok_or_else(|| StdError::generic_err("RecipeGen storage is corrupt"))?;

    for upd in updates.into_iter() {
        let ing_idx = ingredients
            .iter()
            .position(|i| *i == upd.ingredient)
            .ok_or_else(|| {
                StdError::generic_err(format!("{} is not a known ingredient", upd.ingredient))
            })?;
        rec_gen.rarities[ing_idx] = upd.commonality;
    }
    save(deps.storage, RECIPE_GEN_KEY, &rec_gen)?;

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::Ingredients {
            ingredients: ingredients
                .into_iter()
                .zip(rec_gen.rarities.into_iter())
                .map(|(ingredient, commonality)| IngredientCommonality {
                    ingredient,
                    commonality,
                })
                .collect::<Vec<IngredientCommonality>>(),
        })?),
    )
}

/// Returns StdResult<Response>
///
/// override potions used to build the potion list for addition and full reroll potions
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `overrides` - list of CategoryRepOverride to perform
fn try_rep_override(
    deps: DepsMut,
    sender: &Addr,
    overrides: Vec<CategoryRepOverride>,
) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;
    let categories = may_load::<Vec<String>>(deps.storage, CATEGORIES_KEY)?.unwrap_or_default();
    let mut trn_st: TransmuteState = load(deps.storage, TRANSMUTE_STATE_KEY)?;
    let mut rul_store = PrefixedStorage::new(deps.storage, PREFIX_POTION_RULES);

    for over in overrides.into_iter() {
        let cat_idx = if let Some(idx) = over.category_by_index {
            idx as usize
        } else if let Some(name) = over.category_by_name {
            categories
                .iter()
                .position(|cat| *cat == name)
                .ok_or_else(|| {
                    StdError::generic_err(format!("{} is not a valid category name", name))
                })?
        } else {
            return Err(StdError::generic_err(
                "Neither index nor name was provided for the category",
            ));
        };
        let new_rep = over.potion_index.unwrap_or(u16::MAX);
        change_cat_rep(
            &mut rul_store,
            &mut trn_st.build_list,
            cat_idx,
            new_rep,
            true,
        )?;
    }
    save(deps.storage, TRANSMUTE_STATE_KEY, &trn_st)?;
    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::OverrideCategoryRep {
            build_list: trn_st.build_list,
        })?),
    )
}

/// Returns StdResult<Response>
///
/// define the staking tables
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `tables` - list of ingredient sets and their weights for specified materials
fn try_stake_tbl(deps: DepsMut, sender: &Addr, tables: Vec<StakingTable>) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;
    let ingr_sets: Vec<StoredIngrSet> =
        may_load(deps.storage, INGRED_SETS_KEY)?.unwrap_or_default();
    let materials: Vec<String> = may_load(deps.storage, MATERIALS_KEY)?.unwrap_or_default();

    for tbl in tables.into_iter() {
        let mut weights: Vec<StoredSetWeight> = Vec::new();
        let mat = if let Some(pos) = materials.iter().position(|m| *m == tbl.material) {
            pos as u8
        } else {
            return Err(StdError::generic_err(format!(
                "{} is not a known skull material",
                tbl.material
            )));
        };
        let mat_key = mat.to_le_bytes();
        for st_wt in tbl.ingredient_set_weights.into_iter() {
            let set = if let Some(set_pos) = ingr_sets
                .iter()
                .position(|s| s.name == st_wt.ingredient_set)
            {
                set_pos as u8
            } else {
                return Err(StdError::generic_err(format!(
                    "{} is not a known IngredientSet",
                    st_wt.ingredient_set
                )));
            };
            if weights.iter().any(|w| w.set == set) {
                return Err(StdError::generic_err(format!(
                    "{} has been duplicated in the staking table",
                    st_wt.ingredient_set
                )));
            }
            weights.push(StoredSetWeight {
                set,
                weight: st_wt.weight,
            });
        }
        let mut tbl_store = PrefixedStorage::new(deps.storage, PREFIX_STAKING_TABLE);
        save(&mut tbl_store, &mat_key, &weights)?;
    }
    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::SetStakingTables {
            status: "success".to_string(),
        })?),
    )
}

/// Returns StdResult<Response>
///
/// add potion images
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `images` - list of potion image svgs to add
fn try_add_image(deps: DepsMut, sender: &Addr, images: Vec<String>) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;
    let mut alc_st: AlchemyState = load(deps.storage, ALCHEMY_STATE_KEY)?;
    for img in images.into_iter() {
        let mut img_store = PrefixedStorage::new(deps.storage, PREFIX_POTION_IMAGE);
        save(&mut img_store, &alc_st.ptn_img_total.to_le_bytes(), &img)?;
        let mut pool_store = PrefixedStorage::new(deps.storage, PREFIX_IMAGE_POOL);
        save(
            &mut pool_store,
            &alc_st.img_pool_cnt.to_le_bytes(),
            &alc_st.ptn_img_total,
        )?;
        alc_st.ptn_img_total = alc_st.ptn_img_total.checked_add(1).ok_or_else(|| {
            StdError::generic_err("Reached implementation limit for potion images")
        })?;
        // don't need to check overflow because this will never be greater than the total
        alc_st.img_pool_cnt += 1;
    }
    save(deps.storage, ALCHEMY_STATE_KEY, &alc_st)?;
    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::PotionImages {
            unassigned_images: alc_st.img_pool_cnt,
        })?),
    )
}

/// Returns StdResult<Response>
///
/// delete unassigned potion images
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `indices` - list of potion image indices to delete
fn try_del_image(deps: DepsMut, sender: &Addr, mut indices: Vec<u16>) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;
    let mut alc_st: AlchemyState = load(deps.storage, ALCHEMY_STATE_KEY)?;
    // sort the indices in descending order an remove duplicates so subsequent deletes are not
    // affected
    indices.sort_by(|a, b| b.cmp(a));
    indices.dedup();
    let mut pool_store = PrefixedStorage::new(deps.storage, PREFIX_IMAGE_POOL);
    for idx in indices.into_iter() {
        if idx >= alc_st.img_pool_cnt {
            return Err(StdError::generic_err("Index out of bounds"));
        }
        alc_st.img_pool_cnt = alc_st
            .img_pool_cnt
            .checked_sub(1)
            .ok_or_else(|| StdError::generic_err("There are no images in the potion image pool"))?;
        // if deleting the last one, we're done
        if idx != alc_st.img_pool_cnt {
            // get the last image key
            let last = may_load::<u16>(&pool_store, &alc_st.img_pool_cnt.to_le_bytes())?
                .ok_or_else(|| StdError::generic_err("Potion image key pool storage is corrupt"))?;
            // replace the deleted image index
            save(&mut pool_store, &idx.to_le_bytes(), &last)?;
        }
    }
    save(deps.storage, ALCHEMY_STATE_KEY, &alc_st)?;
    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::PotionImages {
            unassigned_images: alc_st.img_pool_cnt,
        })?),
    )
}

/// Returns StdResult<Response>
///
/// define ingredients sets for staking tables
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `sets` - list of ingredient sets
fn try_set_ingred_set(
    deps: DepsMut,
    sender: &Addr,
    sets: Vec<IngredientSet>,
) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;

    let ingredients: Vec<String> = may_load(deps.storage, INGREDIENTS_KEY)?.unwrap_or_default();
    let mut ingr_sets: Vec<StoredIngrSet> =
        may_load(deps.storage, INGRED_SETS_KEY)?.unwrap_or_default();
    for set in sets.into_iter() {
        let mut list: Vec<u8> = Vec::new();
        for member in set.members.iter() {
            if let Some(pos) = ingredients.iter().position(|ing| ing == member) {
                let pos8 = pos as u8;
                if !list.contains(&pos8) {
                    list.push(pos8);
                }
            } else {
                return Err(StdError::generic_err(format!(
                    "{} is not a known ingredient",
                    member
                )));
            }
        }
        if let Some(old_set) = ingr_sets.iter_mut().find(|s| s.name == set.name) {
            old_set.list = list;
        } else {
            ingr_sets.push(StoredIngrSet {
                name: set.name,
                list,
            });
        }
    }
    save(deps.storage, INGRED_SETS_KEY, &ingr_sets)?;

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::DefineIngredientSets {
            count: ingr_sets.len() as u8,
        })?),
    )
}

/// Returns StdResult<Response>
///
/// add ingredient names
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `ingr_to_add` - list of ingredient names and commonalities to add
fn try_add_ingredients(
    deps: DepsMut,
    sender: &Addr,
    ingr_to_add: Vec<IngredientCommonality>,
) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;
    let mut ingredients: Vec<String> = may_load(deps.storage, INGREDIENTS_KEY)?.unwrap_or_default();
    let mut rec_gen = may_load::<RecipeGen>(deps.storage, RECIPE_GEN_KEY)?
        .ok_or_else(|| StdError::generic_err("RecipeGen storage is corrupt"))?;
    for ingr in ingr_to_add.into_iter() {
        if !ingredients.contains(&ingr.ingredient) {
            ingredients.push(ingr.ingredient);
            rec_gen.rarities.push(ingr.commonality);
            rec_gen.usage.push(0);
        }
    }
    save(deps.storage, INGREDIENTS_KEY, &ingredients)?;
    save(deps.storage, RECIPE_GEN_KEY, &rec_gen)?;
    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::Ingredients {
            ingredients: ingredients
                .into_iter()
                .zip(rec_gen.rarities.into_iter())
                .map(|(ingredient, commonality)| IngredientCommonality {
                    ingredient,
                    commonality,
                })
                .collect::<Vec<IngredientCommonality>>(),
        })?),
    )
}

/// Returns StdResult<Response>
///
/// get dependencies and skipped categories form the svg server
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `env` - Env of contract's environment
fn try_get_deps(deps: DepsMut, sender: &Addr, env: Env) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;
    let svg_server = load::<StoreContractInfo>(deps.storage, SVG_SERVER_KEY)
        .and_then(|s| s.into_humanized(deps.api))?;
    let viewing_key: String = load(deps.storage, MY_VIEWING_KEY)?;
    let viewer = ViewerInfo {
        address: env.contract.address.into_string(),
        viewing_key,
    };
    // get the dependencies and the skips
    let srv_alc = ServerQueryMsg::ServeAlchemy { viewer }
        .query::<_, ServeAlchemyWrapper>(deps.querier, svg_server.code_hash, svg_server.address)?
        .serve_alchemy;
    save(deps.storage, DEPENDENCIES_KEY, &srv_alc.dependencies)?;

    let mut trn_st: TransmuteState = load(deps.storage, TRANSMUTE_STATE_KEY)?;
    let categories = may_load::<Vec<String>>(deps.storage, CATEGORIES_KEY)?.unwrap_or_default();
    let cat_cnt = categories.len() as u8;
    trn_st.build_list = vec![u16::MAX; cat_cnt as usize];
    let var_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_VARIANTS);
    trn_st.nones = Vec::new();
    for i in 0..cat_cnt {
        let var_names = may_load::<Vec<String>>(&var_store, &i.to_le_bytes())?.unwrap_or_default();
        // find the none index
        let none_idx = if let Some(pos) = var_names.iter().position(|v| v == "None") {
            pos as u8
        } else {
            255u8
        };
        trn_st.nones.push(none_idx);
    }
    trn_st.skip = srv_alc.skip;
    save(deps.storage, TRANSMUTE_STATE_KEY, &trn_st)?;

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::GetDependencies {
            skip: trn_st.skip,
            nones: trn_st.nones,
        })?),
    )
}

/// Returns StdResult<Response>
///
/// get category and variant names and indices of a specified category from the svg server
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `env` - Env of contract's environment
/// * `idx` - index of the category
fn try_get_names(deps: DepsMut, sender: &Addr, env: Env, idx: u8) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;
    let svg_server = load::<StoreContractInfo>(deps.storage, SVG_SERVER_KEY)
        .and_then(|s| s.into_humanized(deps.api))?;
    let viewing_key: String = load(deps.storage, MY_VIEWING_KEY)?;
    let viewer = ViewerInfo {
        address: env.contract.address.into_string(),
        viewing_key,
    };
    // get the names
    let lyr_nm = ServerQueryMsg::LayerNames { viewer, idx }
        .query::<_, LayerNamesWrapper>(deps.querier, svg_server.code_hash, svg_server.address)?
        .layer_names;
    let mut categories = may_load::<Vec<String>>(deps.storage, CATEGORIES_KEY)?.unwrap_or_default();
    let size_idx = idx as usize;
    if size_idx >= categories.len() {
        categories.resize_with(size_idx + 1, String::new);
    }
    categories[size_idx] = lyr_nm.category_name.clone();
    save(deps.storage, CATEGORIES_KEY, &categories)?;
    let mut is_skull = false;
    let mut is_jaw = false;
    let mut is_eye_type = false;
    let mut materials: Vec<String> = Vec::new();
    let var_cnt = lyr_nm.variants.len();
    if lyr_nm.category_name == *"Skull" {
        // save the skull category index
        let mut stk_st: StakingState = load(deps.storage, STAKING_STATE_KEY)?;
        stk_st.skull_idx = lyr_nm.category_idx;
        save(deps.storage, STAKING_STATE_KEY, &stk_st)?;
        let mut trn_st: TransmuteState = load(deps.storage, TRANSMUTE_STATE_KEY)?;
        trn_st.skull_idx = stk_st.skull_idx;
        save(deps.storage, TRANSMUTE_STATE_KEY, &trn_st)?;
        materials.resize_with(var_cnt, String::new);
        is_skull = true;
    } else if lyr_nm.category_name == *"Eye Type" {
        is_eye_type = true;
    } else if lyr_nm.category_name == *"Jaw Type" {
        is_jaw = true;
    }
    // if doing eye or jaw type
    if is_eye_type || is_jaw {
        let mut trn_st: TransmuteState = load(deps.storage, TRANSMUTE_STATE_KEY)?;
        let (var_name, err_msg, layer) = if is_eye_type {
            // cyclops layer
            (
                "Eye Type.Cyclops",
                "No variant named Eye Type.Cyclops",
                &mut trn_st.cyclops,
            )
        } else {
            // jawless layer
            (
                "None",
                "Missing None variant for Jaw Type",
                &mut trn_st.jawless,
            )
        };
        layer.category = lyr_nm.category_idx;
        layer.variant = lyr_nm
            .variants
            .iter()
            .find(|v| v.name == var_name)
            .ok_or_else(|| StdError::generic_err(err_msg))?
            .idx;
        save(deps.storage, TRANSMUTE_STATE_KEY, &trn_st)?;
    }
    let mut variants: Vec<String> = vec![String::new(); var_cnt];
    for idx_name in lyr_nm.variants.iter() {
        variants[idx_name.idx as usize] = idx_name.name.to_string();
        if is_skull {
            let split: Vec<&str> = idx_name.name.split('.').collect();
            materials[idx_name.idx as usize] = split[1].to_string();
        }
    }
    if variants.iter().any(|n| *n == String::new()) {
        return Err(StdError::generic_err("Blank Name in variant list"));
    }
    if is_skull {
        save(deps.storage, MATERIALS_KEY, &materials)?;
    }
    let mut var_store = PrefixedStorage::new(deps.storage, PREFIX_VARIANTS);
    save(
        &mut var_store,
        &lyr_nm.category_idx.to_le_bytes(),
        &variants,
    )?;

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::GetLayerNames {
            category_name: lyr_nm.category_name,
            category_idx: lyr_nm.category_idx,
            variants: lyr_nm.variants,
        })?),
    )
}

/// Returns StdResult<Response>
///
/// creates a viewing key
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - a reference to the Env of contract's environment
/// * `info` - calling message information MessageInfo
/// * `entropy` - string slice of the input String to be used as entropy in randomization
fn try_create_key(
    deps: DepsMut,
    env: &Env,
    info: &MessageInfo,
    entropy: &str,
) -> StdResult<Response> {
    let key = ViewingKey::create(
        deps.storage,
        info,
        env,
        info.sender.as_str(),
        entropy.as_ref(),
    );
    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::ViewingKey { key })?))
}

/// Returns StdResult<Response>
///
/// sets the viewing key to the input String
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `key` - String to be used as the viewing key
fn try_set_key(deps: DepsMut, sender: &Addr, key: String) -> StdResult<Response> {
    ViewingKey::set(deps.storage, sender.as_str(), &key);

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::ViewingKey { key })?))
}

/// Returns StdResult<Response>
///
/// revoke the ability to use a specified permit
///
/// # Arguments
///
/// * `storage` - mutable reference to the contract's storage
/// * `sender` - a reference to the message sender address
/// * `permit_name` - string slice of the name of the permit to revoke
fn revoke_permit(
    storage: &mut dyn Storage,
    sender: &Addr,
    permit_name: &str,
) -> StdResult<Response> {
    RevokedPermits::revoke_permit(
        storage,
        PREFIX_REVOKED_PERMITS,
        sender.as_str(),
        permit_name,
    );

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::RevokePermit {
            status: "success".to_string(),
        })?),
    )
}

/////////////////////////////////////// Query /////////////////////////////////////
/// Returns StdResult<Binary>
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `msg` - QueryMsg passed in with the query call
#[entry_point]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    let response = match msg {
        QueryMsg::Admins { viewer, permit } => {
            query_admins(deps, viewer, permit, &env.contract.address)
        }
        QueryMsg::NameKeywords { viewer, permit } => {
            query_keywords(deps, viewer, permit, &env.contract.address)
        }
        QueryMsg::Commonalities { viewer, permit } => {
            query_commonality(deps, viewer, permit, &env.contract.address)
        }
        QueryMsg::HaltStatuses {} => query_halt(deps.storage),
        QueryMsg::Contracts {} => query_contracts(deps),
        QueryMsg::Counts {} => query_counts(deps.storage),
        QueryMsg::MyStaking { viewer, permit } => query_my_stake(deps, env, viewer, permit),
        QueryMsg::MyIngredients { viewer, permit } => {
            query_my_inv(deps, viewer, permit, &env.contract.address)
        }
        QueryMsg::UserEligibleForBonus { viewer, permit } => {
            query_user_bonus(deps, viewer, permit, &env.contract.address)
        }
        QueryMsg::TokensEligibleForBonus {
            viewer,
            permit,
            token_ids,
        } => query_token_bonus(deps, env, viewer, permit, token_ids),
        QueryMsg::RewindEligibility {
            viewer,
            permit,
            token_ids,
        } => query_rewind(deps, env, viewer, permit, token_ids),
        QueryMsg::Materials { viewer, permit } => {
            query_mater(deps, viewer, permit, &env.contract.address)
        }
        QueryMsg::Ingredients {} => query_ingr(deps.storage),
        QueryMsg::IngredientSets {
            viewer,
            permit,
            page,
            page_size,
        } => query_ingr_sets(deps, viewer, permit, page, page_size, &env.contract.address),
        QueryMsg::StakingTable {
            viewer,
            permit,
            by_name,
            by_index,
        } => query_stk_tbl(
            deps,
            viewer,
            permit,
            by_name,
            by_index,
            &env.contract.address,
        ),
        QueryMsg::LayerNames {
            viewer,
            permit,
            idx,
            page,
            page_size,
        } => query_layers(
            deps,
            viewer,
            permit,
            idx,
            page,
            page_size,
            &env.contract.address,
        ),
        QueryMsg::Dependencies {
            viewer,
            permit,
            page,
            page_size,
        } => query_deps(deps, viewer, permit, page, page_size, &env.contract.address),
        QueryMsg::PotionRules {
            viewer,
            permit,
            page,
            page_size,
        } => query_rules(deps, viewer, permit, page, page_size, &env.contract.address),
        QueryMsg::ImagePool {
            viewer,
            permit,
            page,
            page_size,
        } => query_pool(deps, viewer, permit, page, page_size, &env.contract.address),
        QueryMsg::MintingMetadata { viewer, permit } => {
            query_meta(deps, viewer, permit, &env.contract.address)
        }
        QueryMsg::States { viewer, permit } => {
            query_state(deps, viewer, permit, &env.contract.address)
        }
    };
    pad_query_result(response, BLOCK_SIZE)
}

/// Returns StdResult<Binary> displaying the potion rules
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `page` - optional page to display
/// * `page_size` - optional number of rules to display
/// * `my_addr` - a reference to this contract's address
fn query_rules(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    page: Option<u16>,
    page_size: Option<u16>,
    my_addr: &Addr,
) -> StdResult<Binary> {
    // only allow admins to do this
    check_admin_query(deps, viewer, permit, my_addr)?;

    let alc_st: AlchemyState = load(deps.storage, ALCHEMY_STATE_KEY)?;
    let trn_st: TransmuteState = load(deps.storage, TRANSMUTE_STATE_KEY)?;
    let page = page.unwrap_or(0);
    let limit = page_size.unwrap_or(5);
    let start = page * limit;
    let end = min(start + limit, alc_st.potion_cnt);
    let categories = may_load::<Vec<String>>(deps.storage, CATEGORIES_KEY)?.unwrap_or_default();
    let cat_cnt = categories.len();
    let mut vars = vec![Vec::new(); cat_cnt];
    let rul_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_POTION_RULES);
    let p2r_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_POTION_IDX_2_RECIPE);
    let add_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_POTION_META_ADD);
    let rc2nm_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_RECIPE_2_NAME);
    let mut keywords = Vec::new();
    let mut potion_rules = Vec::new();

    // TODO remove
    let ingredients: Vec<String> = may_load(deps.storage, INGREDIENTS_KEY)?.unwrap_or_default();
    let found_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_POTION_FOUND);

    let built_list = trn_st
        .build_list
        .into_iter()
        .filter_map(|u| {
            if u != u16::MAX && !alc_st.disabled.contains(&u) {
                Some(PotionWeight { idx: u, weight: 1 })
            } else {
                None
            }
        })
        .collect::<Vec<PotionWeight>>();
    for idx in start..end {
        let is_disabled = alc_st.disabled.contains(&idx);
        let ptn_key = idx.to_le_bytes();
        if let Some(mut rules) = may_load::<StoredPotionRules>(&rul_store, &ptn_key)? {
            let meta_add = may_load::<MetaAdd>(&add_store, &ptn_key)?.ok_or_else(|| {
                StdError::generic_err("Additional potion metadata storage is corrupt")
            })?;
            // TODO remove testing
            let recipe_raw = may_load::<Vec<u8>>(&p2r_store, &ptn_key)?
                .ok_or_else(|| StdError::generic_err("Potion to recipe storage is corrupt"))?;
            let encoded = may_load::<Vec<u8>>(&rc2nm_store, recipe_raw.as_slice())?
                .ok_or_else(|| StdError::generic_err("Recipe to name storage is corrupt"))?;
            let testing = Testing {
                name: derive_name(deps.storage, encoded.as_slice(), &mut keywords)?,
                found: may_load::<bool>(&found_store, &ptn_key)?.is_some(),
                recipe: recipe_raw
                    .iter()
                    .map(|u| ingredients[*u as usize].clone())
                    .collect::<Vec<String>>(),
                image_key: meta_add.image,
                complexity: rules.complex,
                commonality: rules.rare,
            };

            if rules.build_list {
                rules.potion_weights = built_list.clone();
            }
            potion_rules.push(DisplayPotionRules {
                potion_idx: idx,
                normal_weights: rules
                    .normal_weights
                    .iter()
                    .map(|w| w.to_display(deps.storage, &categories, &mut vars))
                    .collect::<StdResult<Vec<TraitWeight>>>()?,
                jawless_weights: rules
                    .jawless_weights
                    .iter()
                    .map(|w| w.to_display(deps.storage, &categories, &mut vars))
                    .collect::<StdResult<Vec<TraitWeight>>>()?,
                cyclops_weights: rules
                    .cyclops_weights
                    .iter()
                    .map(|w| w.to_display(deps.storage, &categories, &mut vars))
                    .collect::<StdResult<Vec<TraitWeight>>>()?,
                potion_weights: rules.potion_weights,
                required_traits: rules
                    .required
                    .iter()
                    .map(|l| l.to_display(deps.storage, &categories, &mut vars))
                    .collect::<StdResult<Vec<VariantList>>>()?,
                description_postscript: meta_add.desc,
                is_addition_potion: rules.is_add,
                do_all_listed_potions: rules.do_all,
                dye_style: rules.dye_style,
                is_disabled,
                jaw_only: trn_st.jaw_only.contains(&idx),
                builds_potion_list: rules.build_list,
                category_rep: rules.cat_rep,
                testing,
            });
        }
    }

    to_binary(&QueryAnswer::PotionRules {
        count: alc_st.potion_cnt,
        potion_rules,
    })
}

/// Returns StdResult<Binary> displaying unassigned potion images
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `page` - optional page to display
/// * `page_size` - optional number of images to display
/// * `my_addr` - a reference to this contract's address
fn query_pool(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    page: Option<u16>,
    page_size: Option<u16>,
    my_addr: &Addr,
) -> StdResult<Binary> {
    // only allow admins to do this
    check_admin_query(deps, viewer, permit, my_addr)?;
    let pool_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_IMAGE_POOL);
    let img_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_POTION_IMAGE);
    let alc_st: AlchemyState = load(deps.storage, ALCHEMY_STATE_KEY)?;
    let page = page.unwrap_or(0);
    let limit = page_size.unwrap_or(10);
    let start = page * limit;
    let end = min(start + limit, alc_st.img_pool_cnt);
    let mut potion_images = Vec::new();
    for idx in start..end {
        if let Some(img_key) = may_load::<u16>(&pool_store, &idx.to_le_bytes())? {
            if let Some(image) = may_load::<String>(&img_store, &img_key.to_le_bytes())? {
                potion_images.push(IdxImage { idx, image });
            }
        }
    }

    to_binary(&QueryAnswer::ImagePool {
        count: alc_st.img_pool_cnt,
        potion_images,
    })
}

/// Returns StdResult<Binary> displaying the dependencies
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `page` - optional page to display
/// * `page_size` - optional number of dependencies to display
/// * `my_addr` - a reference to this contract's address
fn query_deps(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    page: Option<u16>,
    page_size: Option<u16>,
    my_addr: &Addr,
) -> StdResult<Binary> {
    // only allow admins to do this
    check_admin_query(deps, viewer, permit, my_addr)?;

    let page = page.unwrap_or(0) as usize;
    let limit = page_size.unwrap_or(30) as usize;
    let skip = page * limit;
    let categories = may_load::<Vec<String>>(deps.storage, CATEGORIES_KEY)?.unwrap_or_default();
    let cat_cnt = categories.len();
    let mut vars = vec![Vec::new(); cat_cnt];

    let depends =
        may_load::<Vec<StoredDependencies>>(deps.storage, DEPENDENCIES_KEY)?.unwrap_or_default();
    let count = depends.len() as u16;

    to_binary(&QueryAnswer::Dependencies {
        count,
        dependencies: depends
            .iter()
            .skip(skip)
            .take(limit)
            .map(|s| s.to_display(deps.storage, &categories, &mut vars))
            .collect::<StdResult<Vec<Dependencies>>>()?,
    })
}

/// Returns StdResult<Binary> displaying the layer names of the specified category
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `idx` - index of the category to display
/// * `page` - optional page to display
/// * `page_size` - optional number of layer names to display
/// * `my_addr` - a reference to this contract's address
fn query_layers(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    idx: u8,
    page: Option<u16>,
    page_size: Option<u16>,
    my_addr: &Addr,
) -> StdResult<Binary> {
    // only allow admins to do this
    check_admin_query(deps, viewer, permit, my_addr)?;

    let mut categories = may_load::<Vec<String>>(deps.storage, CATEGORIES_KEY)?.unwrap_or_default();
    let idx_big = idx as usize;
    let cat_cnt = categories.len();
    if idx_big >= cat_cnt {
        return Err(StdError::generic_err(format!(
            "There are only {} categories loaded",
            cat_cnt
        )));
    }
    let page = page.unwrap_or(0);
    let limit = page_size.unwrap_or(30);
    let skip = (page * limit) as usize;

    let var_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_VARIANTS);
    let var_names = may_load::<Vec<String>>(&var_store, &idx.to_le_bytes())?.unwrap_or_default();
    let count = var_names.len() as u8;

    to_binary(&QueryAnswer::LayerNames {
        category_name: categories.swap_remove(idx_big),
        category_idx: idx,
        count,
        variants: var_names
            .into_iter()
            .enumerate()
            .skip(skip)
            .take(limit as usize)
            .map(|(i, n)| VariantIdxName {
                idx: i as u8,
                name: n,
            })
            .collect::<Vec<VariantIdxName>>(),
    })
}

/// Returns StdResult<Binary> which displays staking and alchemy halt statuses
///
/// # Arguments
///
/// * `storage` - a reference to this contract's storage
fn query_halt(storage: &dyn Storage) -> StdResult<Binary> {
    let stk_st: StakingState = load(storage, STAKING_STATE_KEY)?;
    let alc_st: AlchemyState = load(storage, ALCHEMY_STATE_KEY)?;
    let crt_st: CrateState = load(storage, CRATE_STATE_KEY)?;

    to_binary(&QueryAnswer::HaltStatuses {
        staking_is_halted: stk_st.halt,
        alchemy_is_halted: alc_st.halt,
        crating_is_halted: crt_st.halt,
    })
}

/// Returns StdResult<Binary> which displays the code hashes and addresses
/// of used contract
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
fn query_contracts(deps: Deps) -> StdResult<Binary> {
    let svg_server = load::<StoreContractInfo>(deps.storage, SVG_SERVER_KEY)
        .and_then(|s| s.into_humanized(deps.api))?;
    let skulls_contract = load::<StoreContractInfo>(deps.storage, SKULL_721_KEY)
        .and_then(|s| s.into_humanized(deps.api))?;
    let crate_contracts =
        load::<Vec<StoreContractInfo>>(deps.storage, CRATES_KEY).and_then(|v| {
            v.into_iter()
                .map(|s| s.into_humanized(deps.api))
                .collect::<StdResult<Vec<ContractInfo>>>()
        })?;
    let potion_contracts =
        load::<Vec<StoreContractInfo>>(deps.storage, POTION_721_KEY).and_then(|v| {
            v.into_iter()
                .map(|s| s.into_humanized(deps.api))
                .collect::<StdResult<Vec<ContractInfo>>>()
        })?;

    to_binary(&QueryAnswer::Contracts {
        svg_server,
        skulls_contract,
        crate_contracts,
        potion_contracts,
    })
}

/// Returns StdResult<Binary> displaying the staking table for a specified skull material
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `by_name` - optional material string to display
/// * `by_index` - optional material index to display
/// * `my_addr` - a reference to this contract's address
fn query_stk_tbl(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    by_name: Option<String>,
    by_index: Option<u8>,
    my_addr: &Addr,
) -> StdResult<Binary> {
    // only allow admins to do this
    check_admin_query(deps, viewer, permit, my_addr)?;
    let mut materials: Vec<String> = may_load(deps.storage, MATERIALS_KEY)?.unwrap_or_default();
    let idx = if let Some(nm) = by_name {
        materials
            .iter()
            .position(|m| *m == nm)
            .ok_or_else(|| StdError::generic_err(format!("Unknown material: {}", nm)))?
            as u8
    } else {
        by_index.ok_or_else(|| StdError::generic_err("Must provide either a name or index"))?
    };
    let tbl_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_STAKING_TABLE);
    let tbl = may_load::<Vec<StoredSetWeight>>(&tbl_store, &idx.to_le_bytes())
        .and_then(|s| s.ok_or_else(|| StdError::generic_err("Invalid SetWeight index")))?;
    let ingr_sets: Vec<StoredIngrSet> =
        may_load(deps.storage, INGRED_SETS_KEY)?.unwrap_or_default();

    to_binary(&QueryAnswer::StakingTable {
        staking_table: StakingTable {
            material: materials.swap_remove(idx as usize),
            ingredient_set_weights: tbl
                .iter()
                .map(|s| IngrSetWeight {
                    ingredient_set: ingr_sets[s.set as usize].name.clone(),
                    weight: s.weight,
                })
                .collect::<Vec<IngrSetWeight>>(),
        },
    })
}

/// Returns StdResult<Binary> displaying the ingredient sets
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `page` - optional page to display
/// * `page_size` - optional number of sets to display
/// * `my_addr` - a reference to this contract's address
fn query_ingr_sets(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    page: Option<u16>,
    page_size: Option<u16>,
    my_addr: &Addr,
) -> StdResult<Binary> {
    // only allow admins to do this
    check_admin_query(deps, viewer, permit, my_addr)?;
    let ingr_sets: Vec<StoredIngrSet> =
        may_load(deps.storage, INGRED_SETS_KEY)?.unwrap_or_default();
    let ingredients: Vec<String> = may_load(deps.storage, INGREDIENTS_KEY)?.unwrap_or_default();

    let page = page.unwrap_or(0);
    let limit = page_size.unwrap_or(30);
    let skip = (page * limit) as usize;

    to_binary(&QueryAnswer::IngredientSets {
        ingredient_sets: ingr_sets
            .into_iter()
            .skip(skip)
            .take(limit as usize)
            .map(|s| IngredientSet {
                name: s.name,
                members: s
                    .list
                    .iter()
                    .map(|u| ingredients[*u as usize].clone())
                    .collect::<Vec<String>>(),
            })
            .collect::<Vec<IngredientSet>>(),
    })
}

/// Returns StdResult<Binary> displaying the user's inventory of ingredients
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `my_addr` - a reference to this contract's address
fn query_my_inv(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    my_addr: &Addr,
) -> StdResult<Binary> {
    let (user_raw, _) = get_querier(deps, viewer, permit, my_addr)?;

    // retrieve the user's ingredient inventory
    let inventory = display_inventory(deps.storage, user_raw.as_slice())?;

    to_binary(&QueryAnswer::MyIngredients { inventory })
}

/// Returns StdResult<Binary> displaying whether the user is eligible for the first time staking bonus
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `my_addr` - a reference to this contract's address
fn query_user_bonus(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    my_addr: &Addr,
) -> StdResult<Binary> {
    let (user_raw, _) = get_querier(deps, viewer, permit, my_addr)?;
    let user_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_USER_STAKE);

    to_binary(&QueryAnswer::UserEligibleForBonus {
        is_eligible: may_load::<Vec<String>>(&user_store, user_raw.as_slice())?.is_none(),
    })
}

/// Returns StdResult<Binary> displaying first staking bonus eligibility for the user and
/// specified tokens
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `token_ids` - list of tokens to check
fn query_token_bonus(
    deps: Deps,
    env: Env,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    token_ids: Vec<String>,
) -> StdResult<Binary> {
    let (user_raw, user_hmn) = get_querier(deps, viewer, permit, &env.contract.address)?;
    let stk_state: StakingState = load(deps.storage, STAKING_STATE_KEY)?;
    let user_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_USER_STAKE);
    let user_is_eligible = may_load::<Vec<String>>(&user_store, user_raw.as_slice())?.is_none();
    let mut token_eligibility: Vec<EligibilityInfo> = Vec::new();
    if user_is_eligible {
        let skull_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_SKULL_STAKE);
        let (_, not_owned, _) = verify_ownership(
            deps,
            &user_hmn,
            token_ids.clone(),
            env.contract.address.into_string(),
        )?;
        let now = env.block.time.seconds();
        let cutoff = now - stk_state.cooldown;
        for token_id in token_ids.into_iter() {
            let (is_eligible, claimed_at) = if not_owned.contains(&token_id) {
                (None, None)
            } else {
                let stk_inf = may_load::<SkullStakeInfo>(&skull_store, token_id.as_bytes())?
                    .unwrap_or(SkullStakeInfo {
                        addr: CanonicalAddr::from(Binary::default()),
                        stake: 0,
                        claim: 0,
                    });
                let is_elg = stk_inf.claim <= cutoff;
                let claim = if is_elg { None } else { Some(stk_inf.claim) };
                (Some(is_elg), claim)
            };
            token_eligibility.push(EligibilityInfo {
                token_id,
                is_eligible,
                claimed_at,
            });
        }
    }

    to_binary(&QueryAnswer::TokensEligibleForBonus {
        user_is_eligible,
        token_eligibility,
    })
}

/// Returns StdResult<Binary> displaying information regarding a list of skulls' rewind
/// eligibility
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `token_ids` - list of tokens to check
fn query_rewind(
    deps: Deps,
    env: Env,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    token_ids: Vec<String>,
) -> StdResult<Binary> {
    let (_, user_hmn) = get_querier(deps, viewer, permit, &env.contract.address)?;
    let (id_images, _, _) = verify_ownership(
        deps,
        &user_hmn,
        token_ids.clone(),
        env.contract.address.into_string(),
    )?;
    let rewind_eligibilities = token_ids
        .into_iter()
        .map(|id| {
            let (can_rewind, disqualification) =
                if let Some(id_image) = id_images.iter().find(|idi| idi.id == id) {
                    // is the owner
                    if let Some(err) = can_rewind(&id_image.image) {
                        (Some(false), Some(err))
                    } else {
                        (Some(true), None)
                    }
                } else {
                    // not the owner
                    (None, None)
                };
            RewindStatus {
                token_id: id,
                can_rewind,
                disqualification,
            }
        })
        .collect::<Vec<RewindStatus>>();

    to_binary(&QueryAnswer::RewindEligibility {
        rewind_eligibilities,
    })
}

/// Returns StdResult<Binary> displaying the user's staking skulls and charges as well as
/// their inventory of ingredients
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
fn query_my_stake(
    deps: Deps,
    env: Env,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
) -> StdResult<Binary> {
    let (user_raw, user_hmn) = get_querier(deps, viewer, permit, &env.contract.address)?;
    let stk_state: StakingState = load(deps.storage, STAKING_STATE_KEY)?;
    let user_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_USER_STAKE);
    let user_key = user_raw.as_slice();
    // get staking list
    let may_stk_list = may_load::<Vec<String>>(&user_store, user_key)?;
    let first_stake_bonus_available = may_stk_list.is_none();
    let stk_list = may_stk_list.unwrap_or_default();
    // only show skulls the user still owns
    let id_images = if stk_state.halt {
        Vec::new()
    } else {
        let (idi, _, _) = verify_ownership(
            deps,
            &user_hmn,
            stk_list,
            env.contract.address.into_string(),
        )?;
        idi
    };
    let mut charge_infos: Vec<ChargeInfo> = Vec::new();
    let now = env.block.time.seconds();
    let skull_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_SKULL_STAKE);
    for id_img in id_images.into_iter() {
        // get staking info of each skull
        let id_key = id_img.id.as_bytes();
        let stk_inf = may_load::<SkullStakeInfo>(&skull_store, id_key)?.unwrap_or(SkullStakeInfo {
            addr: CanonicalAddr::from(Binary::default()),
            stake: 0,
            claim: 0,
        });
        // can't claim skulls that are staking with a different user now
        if stk_inf.addr != user_raw {
            continue;
        }
        let time_in_stake = now - stk_inf.stake;
        // calc accrued charges
        let charges = min(4, time_in_stake / stk_state.cooldown) as u8;
        charge_infos.push(ChargeInfo {
            token_id: id_img.id,
            charge_start: stk_inf.stake,
            charges,
        });
    }
    // retrieve the user's ingredient inventory
    let inventory = display_inventory(deps.storage, user_key)?;

    to_binary(&QueryAnswer::MyStaking {
        first_stake_bonus_available,
        charge_infos,
        inventory,
        staking_is_halted: stk_state.halt,
    })
}

/// Returns StdResult<Binary> displaying the list of ingredients
///
/// # Arguments
///
/// * `storage` - a reference to the storage this item is in
fn query_ingr(storage: &dyn Storage) -> StdResult<Binary> {
    let ingredients: Vec<String> = may_load(storage, INGREDIENTS_KEY)?.unwrap_or_default();

    to_binary(&QueryAnswer::Ingredients { ingredients })
}

/// Returns StdResult<Binary> displaying the counts of potions discovered and ingredients
/// consumed
///
/// # Arguments
///
/// * `storage` - a reference to the storage this item is in
fn query_counts(storage: &dyn Storage) -> StdResult<Binary> {
    let alc_st: AlchemyState = load(storage, ALCHEMY_STATE_KEY)?;
    let potions_discovered = alc_st.found_cnt;
    let ingredients_consumed = Uint128::new(may_load::<u128>(storage, CONSUMED_KEY)?.unwrap_or(0));

    to_binary(&QueryAnswer::Counts {
        potions_discovered,
        ingredients_consumed,
    })
}

/// Returns StdResult<Binary> displaying the skull materials and their indices
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `my_addr` - a reference to this contract's address
fn query_mater(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    my_addr: &Addr,
) -> StdResult<Binary> {
    // only allow admins to do this
    check_admin_query(deps, viewer, permit, my_addr)?;
    let materials: Vec<String> = may_load(deps.storage, MATERIALS_KEY)?.unwrap_or_default();

    to_binary(&QueryAnswer::Materials {
        materials: materials
            .into_iter()
            .enumerate()
            .map(|(i, m)| VariantIdxName {
                idx: i as u8,
                name: m,
            })
            .collect::<Vec<VariantIdxName>>(),
    })
}

/// Returns StdResult<Binary> displaying the ingredients and their commonality scores
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `my_addr` - a reference to this contract's address
fn query_commonality(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    my_addr: &Addr,
) -> StdResult<Binary> {
    // only allow admins to do this
    check_admin_query(deps, viewer, permit, my_addr)?;
    let ingredients: Vec<String> = may_load(deps.storage, INGREDIENTS_KEY)?.unwrap_or_default();
    let rec_gen = may_load::<RecipeGen>(deps.storage, RECIPE_GEN_KEY)?
        .ok_or_else(|| StdError::generic_err("RecipeGen storage is corrupt"))?;

    to_binary(&QueryAnswer::Commonalities {
        commonalities: ingredients
            .into_iter()
            .zip(rec_gen.rarities.into_iter())
            .map(|(ingredient, commonality)| IngredientCommonality {
                ingredient,
                commonality,
            })
            .collect::<Vec<IngredientCommonality>>(),
    })
}

/// Returns StdResult<Binary> displaying the staking and alchemy states
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `my_addr` - a reference to this contract's address
fn query_state(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    my_addr: &Addr,
) -> StdResult<Binary> {
    // only allow admins to do this
    check_admin_query(deps, viewer, permit, my_addr)?;
    let staking_state: StakingState = load(deps.storage, STAKING_STATE_KEY)?;
    let alchemy_state: AlchemyState = load(deps.storage, ALCHEMY_STATE_KEY)?;
    let crt_st: CrateState = load(deps.storage, CRATE_STATE_KEY)?;
    let transmute_state: TransmuteState = load(deps.storage, TRANSMUTE_STATE_KEY)?;
    // TODO remove this so can't see usage counts after testing
    let recipe_gen_info: RecipeGen = load(deps.storage, RECIPE_GEN_KEY)?;

    to_binary(&QueryAnswer::States {
        staking_state,
        alchemy_state,
        transmute_state,
        crating_state: DisplayCrateState {
            halt: crt_st.halt,
            cnt: Uint128::new(crt_st.cnt),
        },
        recipe_gen_info,
    })
}

/// Returns StdResult<Binary> displaying the crate and potion metadata
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `my_addr` - a reference to this contract's address
fn query_meta(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    my_addr: &Addr,
) -> StdResult<Binary> {
    // only allow admins to do this
    check_admin_query(deps, viewer, permit, my_addr)?;
    let crate_metadata = may_load::<Metadata>(deps.storage, CRATE_META_KEY)?.unwrap_or_default();
    let potion_metadata = may_load::<Metadata>(deps.storage, POTION_META_KEY)?.unwrap_or_default();

    to_binary(&QueryAnswer::MintingMetadata {
        crate_metadata,
        potion_metadata,
    })
}

/// Returns StdResult<Binary> displaying the keywords used to generate potion names
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `my_addr` - a reference to this contract's address
fn query_keywords(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    my_addr: &Addr,
) -> StdResult<Binary> {
    // only allow admins to do this
    check_admin_query(deps, viewer, permit, my_addr)?;

    let mut keywords = may_load::<Vec<Vec<String>>>(deps.storage, NAME_KEYWORD_KEY)?
        .unwrap_or(vec![Vec::new(); 4]);

    to_binary(&QueryAnswer::NameKeywords {
        fourth: keywords.pop().unwrap(),
        third: keywords.pop().unwrap(),
        second: keywords.pop().unwrap(),
        first: keywords.pop().unwrap(),
    })
}

/// Returns StdResult<Binary> displaying the admin addresses
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `my_addr` - a reference to this contract's address
fn query_admins(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    my_addr: &Addr,
) -> StdResult<Binary> {
    // only allow admins to do this
    let admins = check_admin_query(deps, viewer, permit, my_addr)?;
    to_binary(&QueryAnswer::Admins {
        admins: admins
            .iter()
            .map(|a| deps.api.addr_humanize(a))
            .collect::<StdResult<Vec<Addr>>>()?,
    })
}

/// Returns StdResult<(CanonicalAddr, String)> from determining the querying address
/// either from a Permit or a ViewerInfo
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `my_addr` - a reference to this contract's address
fn get_querier(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    my_addr: &Addr,
) -> StdResult<(CanonicalAddr, String)> {
    if let Some(pmt) = permit {
        // Validate permit content
        let querier = validate(
            deps,
            PREFIX_REVOKED_PERMITS,
            &pmt,
            my_addr.to_string(),
            Some("secret"),
        )?;
        let raw = deps
            .api
            .addr_validate(&querier)
            .and_then(|a| deps.api.addr_canonicalize(a.as_str()))?;
        if !pmt.check_permission(&secret_toolkit::permit::TokenPermissions::Owner) {
            return Err(StdError::generic_err(format!(
                "Owner permission is required for queries, got permissions {:?}",
                pmt.params.permissions
            )));
        }
        return Ok((raw, querier));
    }
    if let Some(vwr) = viewer {
        let hmn = deps.api.addr_validate(&vwr.address)?;
        let raw = deps.api.addr_canonicalize(hmn.as_str())?;
        ViewingKey::check(deps.storage, hmn.as_str(), &vwr.viewing_key).map_err(|_| {
            StdError::generic_err("Wrong viewing key for this address or viewing key not set")
        })?;
        return Ok((raw, vwr.address));
    }
    Err(StdError::generic_err(
        "A permit or viewing key must be provided",
    ))
}

/// Returns StdResult<Vec<CanonicalAddr>> which is the admin list and checks if the querier is an admin
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `my_addr` - a reference to this contract's address
fn check_admin_query(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    my_addr: &Addr,
) -> StdResult<Vec<CanonicalAddr>> {
    let (address, _) = get_querier(deps, viewer, permit, my_addr)?;
    check_admin(deps.storage, &address)
}

/// Returns StdResult<Vec<CanonicalAddr>> which is the admin list and checks if the message
/// sender is an admin
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
fn check_admin_tx(deps: Deps, sender: &Addr) -> StdResult<Vec<CanonicalAddr>> {
    let sender_raw = deps.api.addr_canonicalize(sender.as_str())?;
    check_admin(deps.storage, &sender_raw)
}

/// Returns StdResult<Vec<CanonicalAddr>> which is the admin list and checks if the address
/// is an admin
///
/// # Arguments
///
/// * `storage` - a reference to this contract's storage
/// * `address` - a reference to the address in question
fn check_admin(storage: &dyn Storage, address: &CanonicalAddr) -> StdResult<Vec<CanonicalAddr>> {
    let admins: Vec<CanonicalAddr> = load(storage, ADMINS_KEY)?;
    if !admins.contains(address) {
        return Err(StdError::generic_err("Not an admin"));
    }
    Ok(admins)
}

/// Returns StdResult<Response>
///
/// updates the admin list
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `update_list` - list of addresses to use for update
/// * `is_add` - true if the update is for adding to the list
fn try_process_auth_list(
    deps: DepsMut,
    sender: &Addr,
    update_list: &[String],
    is_add: bool,
) -> StdResult<Response> {
    // only allow admins to do this
    let mut admins = check_admin_tx(deps.as_ref(), sender)?;

    // update the authorization list if needed
    let save_it = if is_add {
        add_addrs_to_auth(deps.api, &mut admins, update_list)?
    } else {
        remove_addrs_from_auth(deps.api, &mut admins, update_list)?
    };
    // save list if it changed
    if save_it {
        save(deps.storage, ADMINS_KEY, &admins)?;
    }
    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::AdminsList {
            admins: admins
                .iter()
                .map(|a| deps.api.addr_humanize(a))
                .collect::<StdResult<Vec<Addr>>>()?,
        })?),
    )
}

/// Returns StdResult<bool>
///
/// adds to an authorization list of addresses and returns true if the list changed
///
/// # Arguments
///
/// * `api` - a reference to the Api used to convert human and canonical addresses
/// * `addresses` - current mutable list of addresses
/// * `addrs_to_add` - list of addresses to add
fn add_addrs_to_auth(
    api: &dyn Api,
    addresses: &mut Vec<CanonicalAddr>,
    addrs_to_add: &[String],
) -> StdResult<bool> {
    let mut save_it = false;
    for addr in addrs_to_add.iter() {
        let raw = api
            .addr_validate(addr)
            .and_then(|a| api.addr_canonicalize(a.as_str()))?;
        if !addresses.contains(&raw) {
            addresses.push(raw);
            save_it = true;
        }
    }
    Ok(save_it)
}

/// Returns StdResult<bool>
///
/// removes from an authorization list of addresses and returns true if the list changed
///
/// # Arguments
///
/// * `api` - a reference to the Api used to convert human and canonical addresses
/// * `addresses` - current mutable list of addresses
/// * `addrs_to_remove` - list of addresses to remove
fn remove_addrs_from_auth(
    api: &dyn Api,
    addresses: &mut Vec<CanonicalAddr>,
    addrs_to_remove: &[String],
) -> StdResult<bool> {
    let old_len = addresses.len();
    let rem_list = addrs_to_remove
        .iter()
        .map(|a| {
            api.addr_validate(a)
                .and_then(|a| api.addr_canonicalize(a.as_str()))
        })
        .collect::<StdResult<Vec<CanonicalAddr>>>()?;
    addresses.retain(|a| !rem_list.contains(a));
    // only save if the list changed
    Ok(old_len != addresses.len())
}

// a skull's token id and the ImageInfo retrieved for it
pub struct IdImage {
    pub id: String,
    pub image: ImageInfo,
}

/// Returns StdResult<(Vec<IdImage>, Vec<String>, ContractInfo)>
///
/// Verifies ownership of a list of skull token ids and returns the list of token ids and image infos for
/// skulls that have been verified to be owned by the specified address, and the list of token ids of the
/// skulls that do not belong to the address.  Also returns the skull 721 contract
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `owner` - a reference to the owner address for verification
/// * `skulls` - list of token ids to check
/// * `my_addr` - this contract's address
fn verify_ownership(
    deps: Deps,
    owner: &str,
    skulls: Vec<String>,
    my_addr: String,
) -> StdResult<(Vec<IdImage>, Vec<String>, ContractInfo)> {
    let mut owned: Vec<IdImage> = Vec::new();
    let mut not_owned: Vec<String> = Vec::new();
    let viewing_key: String = load(deps.storage, MY_VIEWING_KEY)?;
    let viewer = ViewerInfo {
        address: my_addr,
        viewing_key,
    };
    let skull_contract = load::<StoreContractInfo>(deps.storage, SKULL_721_KEY)
        .and_then(|s| s.into_humanized(deps.api))?;

    for id in skulls.into_iter() {
        // see if this is a duplicate in the list
        if owned.iter().any(|i| i.id == id) {
            continue;
        }
        if not_owned.contains(&id) {
            continue;
        }
        // get the image info
        let img_inf_resp = Snip721QueryMsg::ImageInfo {
            token_id: id.clone(),
            viewer: viewer.clone(),
        }
        .query::<_, ImageInfoWrapper>(
            deps.querier,
            skull_contract.code_hash.clone(),
            skull_contract.address.clone(),
        )?
        .image_info;
        // if not the current owner
        if img_inf_resp.owner != *owner {
            not_owned.push(id);
        } else {
            owned.push(IdImage {
                id,
                image: img_inf_resp.image_info,
            });
        }
    }
    Ok((owned, not_owned, skull_contract))
}

/// Returns StdResult<Vec<u32>>
///
/// Take a list of charges per material type, and randomly draw resources according to the weighted staking table
///
/// # Arguments
///
/// * `storage` - a reference to this contract's storage
/// * `env` - a reference to the Env of contract's environment
/// * `charges` - number of charges per material type
/// * `quantities` - number of skulls per material type
/// * `ingr_cnt` - number of different ingredients
fn gen_resources(
    storage: &dyn Storage,
    env: &Env,
    charges: &[u8],
    quantities: &[u8],
    ingr_cnt: usize,
) -> StdResult<Vec<u32>> {
    let mut generated: Vec<u32> = vec![0; ingr_cnt];
    let mut rng = ContractPrng::from_env(env);
    let type_cnt = quantities.iter().filter(|&q| *q > 0).count() as u64;
    let variety_lim = (2 * type_cnt) + 1;
    let ingr_sets: Vec<StoredIngrSet> = may_load(storage, INGRED_SETS_KEY)?.unwrap_or_default();
    let mut wins_per_set: Vec<u16> = vec![0; ingr_sets.len()];
    // go through each material type and the number of charges for each
    for (i, charge) in charges.iter().enumerate() {
        // process each charge for this material type
        for _ in 0u8..*charge {
            // randomly determine number of resources generated for this charge
            let rdm_mat = rng.next_u64();
            let rdm_var = rng.next_u64();
            let rolls: u8 =
                1 + (rdm_mat % (quantities[i] as u64 + 1u64)) as u8 + (rdm_var % variety_lim) as u8;
            let tbl_store = ReadonlyPrefixedStorage::new(storage, PREFIX_STAKING_TABLE);
            let i_sml = i as u8;
            let stk_tbl: Vec<StoredSetWeight> = load(&tbl_store, &i_sml.to_le_bytes())?;
            let just_weights: Vec<u16> = stk_tbl.iter().map(|t| t.weight).collect();
            let total_weight: u16 = just_weights.iter().sum();
            // randomly pick the winning ingredient set for each resource
            for _ in 0u8..rolls {
                let rdm = rng.next_u64();
                let winning_num: u16 = (rdm % total_weight as u64) as u16;
                let mut tally = 0u16;
                let mut winner = 0usize;
                for set_weight in stk_tbl.iter() {
                    // if the sum didn't panic on overflow, it can't happen here
                    tally += set_weight.weight;
                    if tally > winning_num {
                        winner = set_weight.set as usize;
                        break;
                    }
                }
                // increment wins for the winning ingredient set
                wins_per_set[winner] += 1;
            }
        }
    }
    // randomly pick ingredients from each winning set of ingredients
    for (idx, resource_cnt) in wins_per_set.iter().enumerate() {
        // if this set had been picked
        if *resource_cnt > 0 {
            // number of ingredients to pick from
            let ingr_cnt = ingr_sets[idx].list.len() as u64;
            for _ in 0u16..*resource_cnt {
                let win = if ingr_cnt == 1 {
                    // no need to waste resources getting a rdm number if there is only one possible
                    0usize
                } else {
                    // more than one ingredient in this set
                    let rdm_ing = rng.next_u64();
                    (rdm_ing % ingr_cnt) as usize
                };
                generated[ingr_sets[idx].list[win] as usize] += 1;
            }
        }
    }
    Ok(generated)
}

/// Returns StdResult<Vec<IngredientQty>>
///
/// generate resources for the charges and update user ingredients inventory
///
/// # Arguments
///
/// * `storage` - a mutable reference to this contract's storage
/// * `env` - a reference to the Env of contract's environment
/// * `charges` - number of charges per material type
/// * `quantities` - number of skulls per material type
/// * `user_key` - user address storage key
fn process_charges(
    storage: &mut dyn Storage,
    env: &Env,
    charges: &[u8],
    quantities: &[u8],
    user_key: &[u8],
) -> StdResult<Vec<IngredientQty>> {
    // get ingredient list and user's inventory
    let (ingredients, mut raw_inv) = get_inventory(storage, user_key)?;
    let ingr_cnt = ingredients.len();
    // generate the ingredients
    let generated = gen_resources(storage, env, charges, quantities, ingr_cnt)?;
    // add the newly generated resources
    for (inv, new) in raw_inv.iter_mut().zip(&generated) {
        *inv += *new;
    }
    let mut inv_store = PrefixedStorage::new(storage, PREFIX_USER_INGR_INVENTORY);
    save(&mut inv_store, user_key, &raw_inv)?;
    // create the list of generated resources for the output
    Ok(ingredients
        .into_iter()
        .zip(generated.into_iter())
        .filter_map(|(ingredient, quantity)| {
            if quantity > 0 {
                Some(IngredientQty {
                    ingredient,
                    quantity,
                })
            } else {
                None
            }
        })
        .collect::<Vec<IngredientQty>>())
}

/// Returns StdResult<Vec<IngredientQty>>
///
/// create a readable list of a user's ingredient inventory
///
/// # Arguments
///
/// * `storage` - a reference to this contract's storage
/// * `user_key` - user address storage key
fn display_inventory(storage: &dyn Storage, user_key: &[u8]) -> StdResult<Vec<IngredientQty>> {
    // get the ingredient list and the user's inventory
    let (ingredients, raw_inv) = get_inventory(storage, user_key)?;
    // create the readable list of ingredients
    Ok(ingredients
        .into_iter()
        .zip(raw_inv.into_iter())
        .map(|(ingredient, quantity)| IngredientQty {
            ingredient,
            quantity,
        })
        .collect::<Vec<IngredientQty>>())
}

/// Returns StdResult<(Vec<String>, Vec<u32>)>
///
/// retrieve the ingredient list and the user's inventory
///
/// # Arguments
///
/// * `storage` - a reference to this contract's storage
/// * `user_key` - user address storage key
fn get_inventory(storage: &dyn Storage, user_key: &[u8]) -> StdResult<(Vec<String>, Vec<u32>)> {
    let ingredients: Vec<String> = may_load(storage, INGREDIENTS_KEY)?.unwrap_or_default();
    let ingr_cnt = ingredients.len();
    let inv_store = ReadonlyPrefixedStorage::new(storage, PREFIX_USER_INGR_INVENTORY);
    let mut raw_inv: Vec<u32> = may_load(&inv_store, user_key)?.unwrap_or_default();
    // just in case new ingredients get added, extend old inventories
    raw_inv.resize(ingr_cnt, 0);
    Ok((ingredients, raw_inv))
}

/// Returns StdResult<Response>
///
/// uncrate crate nfts
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `crate_addr` - the message sender's address
/// * `crate_hash` - the message sender's code hash
/// * `from` - a reference to the address that owned the crate NFTs
/// * `token_ids` - list of tokens sent
fn uncrate(
    deps: DepsMut,
    crate_addr: String,
    crate_hash: String,
    from: &str,
    token_ids: Vec<String>,
) -> StdResult<Response> {
    if token_ids.is_empty() {
        return Err(StdError::generic_err("No crate NFTs were sent"));
    }
    let user_raw = deps
        .api
        .addr_validate(from)
        .and_then(|a| deps.api.addr_canonicalize(a.as_str()))?;
    let user_key = user_raw.as_slice();
    // get the ingredient list and the user's inventory
    let (ingredients, mut raw_inv) = get_inventory(deps.storage, user_key)?;
    let ingr_cnt = ingredients.len();
    // get the public metadata of all nfts sent
    let dossiers = Snip721QueryMsg::BatchNftDossier {
        token_ids: token_ids.clone(),
    }
    .query::<_, BatchNftDossierWrapper>(deps.querier, crate_hash.clone(), crate_addr.clone())?
    .batch_nft_dossier
    .nft_dossiers;
    // burn all the crates sent
    let burns = vec![Burn {
        token_ids,
        memo: None,
    }];
    let mut resp = Response::new().add_message(
        Snip721HandleMsg::BatchBurnNft { burns }.to_cosmos_msg(crate_hash, crate_addr, None)?,
    );
    let mut added: Vec<u32> = vec![0; ingr_cnt];
    // add the crate ingredients to the user inventory
    for dossier in dossiers.into_iter() {
        let attrs = dossier
            .public_metadata
            .extension
            .attributes
            .ok_or_else(|| StdError::generic_err("Crate NFT is missing traits"))?;
        for attr in attrs.into_iter() {
            if let Some(pos) = ingredients.iter().position(|i| *i == attr.trait_type) {
                let qty = attr.value.parse::<u32>().map_err(|e| {
                    StdError::generic_err(format!("Ingredient quantity parse error: {}", e))
                })?;
                raw_inv[pos] += qty;
                added[pos] += qty;
            }
        }
    }
    // create logs for each ingredient added
    for (ing, qty) in ingredients.into_iter().zip(added.iter()) {
        if *qty > 0 {
            resp = resp.add_attribute(ing, qty.to_string());
        }
    }
    let mut inv_store = PrefixedStorage::new(deps.storage, PREFIX_USER_INGR_INVENTORY);
    save(&mut inv_store, user_key, &raw_inv)?;
    Ok(resp)
}

/// Returns StdResult<Response>
///
/// attempt to apply a potion
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `ptn721_addr` - the message sender's address
/// * `ptn721_hash` - the message sender's code hash
/// * `from` - a reference to the address that owned the potion NFT
/// * `token_ids` - list of tokens sent
/// * `msg` - the base64 encoded msg containing the skull to apply the potion to (if applicable)
/// * `disabled` - list of potions that are disabled
fn rcv_potion(
    deps: DepsMut,
    env: Env,
    ptn721_addr: String,
    ptn721_hash: String,
    from: &str,
    mut token_ids: Vec<String>,
    msg: Option<Binary>,
    disabled: &[u16],
) -> StdResult<Response> {
    let pot_id = token_ids
        .pop()
        .ok_or_else(|| StdError::generic_err("No potion NFT was sent"))?;
    let skull_id: String =
        from_binary(&msg.ok_or_else(|| StdError::generic_err("Skull ID was not provided"))?)?;
    let distill = &skull_id == "distill";
    let mut trn_st: TransmuteState = load(deps.storage, TRANSMUTE_STATE_KEY)?;
    // get the name of the potion
    let pot_name = Snip721QueryMsg::NftInfo {
        token_id: pot_id.clone(),
    }
    .query::<_, NftInfoWrapper>(deps.querier, ptn721_hash.clone(), ptn721_addr.clone())?
    .nft_info
    .extension
    .name
    .ok_or_else(|| StdError::generic_err("Potion NFT is missing the potion name"))?;
    let idx_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_NAME_2_POTION_IDX);
    let encode_ptn = encode_name(deps.storage, &pot_name, &mut Vec::new())?;
    let pot_idx = may_load::<u16>(&idx_store, encode_ptn.as_slice())?
        .ok_or_else(|| StdError::generic_err(format!("Unknown potion name {}", pot_name)))?;
    let is_disabled = disabled.contains(&pot_idx);
    let mut messages: Vec<CosmosMsg> = Vec::new();
    let memo: Option<String>;
    let changed_str: String;
    let mut added_inv: Vec<u32>;
    let ingredients: Vec<String>;

    if distill {
        // distill a disabled potion
        if !is_disabled {
            return Err(StdError::generic_err(
                "This potion has not been disabled, you can not distill it",
            ));
        }
        let p2r_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_POTION_IDX_2_RECIPE);
        let recipe = may_load::<Vec<u8>>(&p2r_store, &pot_idx.to_le_bytes())?.ok_or_else(|| {
            StdError::generic_err("The recipe for this potion has not been generated")
        })?;
        let user_raw = deps
            .api
            .addr_validate(from)
            .and_then(|a| deps.api.addr_canonicalize(a.as_str()))?;
        let user_key = user_raw.as_slice();
        // get list of ingredients and the user's inventory
        let (ingr, mut raw_inv) = get_inventory(deps.storage, user_key)?;
        ingredients = ingr;
        let ingr_cnt = ingredients.len();
        added_inv = vec![0; ingr_cnt];
        // increment the recipe ingredients
        for i in recipe.into_iter() {
            let big_i = i as usize;
            raw_inv[big_i] += 1;
            added_inv[big_i] += 1;
        }
        let mut inv_store = PrefixedStorage::new(deps.storage, PREFIX_USER_INGR_INVENTORY);
        save(&mut inv_store, user_key, &raw_inv)?;
        memo = Some("Distilled for ingredients".to_string());
        changed_str = String::new();
    } else {
        if is_disabled {
            return Err(StdError::generic_err(
                "This potion has been disabled, but the ingredients may be distilled",
            ));
        }
        // check if sender owns the skull they are trying to transmute
        let (mut id_images, _, skull_contract) = verify_ownership(
            deps.as_ref(),
            from,
            vec![skull_id],
            env.contract.address.to_string(),
        )?;
        let mut id_image = if let Some(idi) = id_images.pop() {
            idi
        } else {
            return Err(StdError::generic_err(
                "You do not own the skull you are trying to transmute",
            ));
        };
        // can only apply potions to completely revealed skulls
        if id_image.image.current.iter().any(|u| *u == 255) {
            return Err(StdError::generic_err(
                "Potions can only be applied to completely revealed skulls",
            ));
        }
        // save the starting appearance
        let old_image = id_image.image.current.clone();
        let mut prng = ContractPrng::from_env(&env);
        let mut potions = vec![pot_idx];
        let depends = may_load::<Vec<StoredDependencies>>(deps.storage, DEPENDENCIES_KEY)?
            .unwrap_or_default();
        let is_jawless = old_image[trn_st.jawless.category as usize] == trn_st.jawless.variant;
        let is_cyclops = old_image[trn_st.cyclops.category as usize] == trn_st.cyclops.variant;
        // filter disabled potions from the build list
        for bld in trn_st.build_list.iter_mut() {
            if disabled.contains(bld) {
                *bld = u16::MAX;
            }
        }

        // keep applying until we are done with all potions
        while !potions.is_empty() {
            apply_potion(
                deps.storage,
                &mut prng,
                &mut id_image.image.current,
                &trn_st,
                &depends,
                &mut potions,
                is_jawless,
                is_cyclops,
                disabled,
            )?;
        }

        // check if the skull image changed
        if old_image == id_image.image.current {
            return Err(StdError::generic_err("The skull resisted transmutation"));
        }
        // change to transmuted background if this is the first transmutation
        if id_image.image.current[0] < 6 {
            let var_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_VARIANTS);
            let backgrs =
                may_load::<Vec<String>>(&var_store, &0u8.to_le_bytes())?.unwrap_or_default();
            let new_back = format!("{} Transmuted", backgrs[id_image.image.current[0] as usize]);
            let new_idx = backgrs.iter().position(|b| *b == new_back).ok_or_else(|| {
                StdError::generic_err(format!(
                    "Unable to find corresponding transmuted background {}",
                    new_back
                ))
            })?;
            id_image.image.current[0] = new_idx as u8;
        }
        // get categories that have changed
        let categories = may_load::<Vec<String>>(deps.storage, CATEGORIES_KEY)?.unwrap_or_default();
        let zipped_image = id_image.image.current.iter().zip(old_image.iter());
        let changed = categories
            .into_iter()
            .enumerate()
            .zip(zipped_image)
            .filter_map(|((i, s), (c, o))| {
                if *c != *o && !trn_st.skip.contains(&(i as u8)) {
                    Some(s)
                } else {
                    None
                }
            })
            .collect::<Vec<String>>();
        changed_str = format!("{:?}", changed);
        // rewind save point
        id_image.image.previous = old_image;
        memo = Some(format!("{} applied to skull {}", pot_name, id_image.id));
        added_inv = Vec::new();
        ingredients = Vec::new();
        // update the skull image
        messages.push(
            Snip721HandleMsg::SetImageInfo {
                token_id: id_image.id,
                image_info: id_image.image,
            }
            .to_cosmos_msg(skull_contract.code_hash, skull_contract.address, None)?,
        );
    }
    // burn the potion
    messages.push(
        Snip721HandleMsg::BatchBurnNft {
            burns: vec![Burn {
                token_ids: vec![pot_id],
                memo,
            }],
        }
        .to_cosmos_msg(ptn721_hash, ptn721_addr, None)?,
    );
    let mut resp = Response::new().add_messages(messages);
    if !distill {
        // applied a potion
        // create log of categories changed
        resp = resp.add_attribute("Transmuted Categories", changed_str);
    } else {
        // distilled a potion
        // create logs for each ingredient added
        for (ing, qty) in ingredients.into_iter().zip(added_inv.iter()) {
            if *qty > 0 {
                resp = resp.add_attribute(ing, qty.to_string());
            }
        }
    }
    Ok(resp)
}

/// Returns StdResult<()>
///
/// apply a potion to a skull's image
///
/// # Arguments
///
/// * `storage` - a reference to this contract's storage
/// * `prng` - a mutable reference to the ContractPrng used to draw random selections
/// * `image` - a mutable reference to the current skull image vec
/// * `trn_st` - a reference to the TransmuteState
/// * `depends` - list of traits that have multiple layers
/// * `potions` - a mutable reference to a list of potions being applied
/// * `is_jawless` - true if the skull is jawless
/// * `is_cyclops` - true if the skull is a cyclops
/// * `disabled` - list of potions that are disabled
fn apply_potion(
    storage: &dyn Storage,
    prng: &mut ContractPrng,
    image: &mut [u8],
    trn_st: &TransmuteState,
    depends: &[StoredDependencies],
    potions: &mut Vec<u16>,
    is_jawless: bool,
    is_cyclops: bool,
    disabled: &[u16],
) -> StdResult<()> {
    let ptn_idx = potions
        .pop()
        .ok_or_else(|| StdError::generic_err("Empty potions index array"))?;
    let rul_store = ReadonlyPrefixedStorage::new(storage, PREFIX_POTION_RULES);
    let mut rules: StoredPotionRules = load(&rul_store, &ptn_idx.to_le_bytes())?;
    // if we need to build a potion list
    if rules.build_list {
        rules.potion_weights = trn_st
            .build_list
            .iter()
            .enumerate()
            .filter_map(|(i, p)| {
                if *p != u16::MAX && (rules.do_all || (rules.is_add && image[i] == trn_st.nones[i]))
                {
                    Some(PotionWeight { idx: *p, weight: 1 })
                } else {
                    None
                }
            })
            .collect::<Vec<PotionWeight>>();
        if rules.potion_weights.is_empty() {
            return Err(StdError::generic_err(
                "This skull can not be affected by this potion",
            ));
        }
    }
    if !rules.potion_weights.is_empty() {
        // filter out disabled potions and jaw-only potions if jawless
        rules.potion_weights.retain(|p| {
            !disabled.contains(&p.idx) && (!is_jawless || !trn_st.jaw_only.contains(&p.idx))
        });
        if rules.potion_weights.is_empty() {
            return Err(StdError::generic_err(
                "This skull can not be affected by this potion",
            ));
        }
    }
    if is_jawless && trn_st.jaw_only.contains(&ptn_idx) {
        return Err(StdError::generic_err(
            "This potion can not be used on jawless skulls",
        ));
    }
    if !rules.required.is_empty()
        && !rules
            .required
            .iter()
            .any(|l| l.vars.contains(&image[l.cat as usize]))
    {
        return Err(StdError::generic_err(
            "This skull does not have any of the required traits for this potion",
        ));
    }
    if rules.do_all {
        // perform multiple potion effects
        potions.append(
            &mut rules
                .potion_weights
                .into_iter()
                .map(|w| w.idx)
                .collect::<Vec<u16>>(),
        );
        return Ok(());
    }
    if rules.potion_weights.is_empty() {
        // will roll from trait weights
        let roll_tbl = if is_jawless && !rules.jawless_weights.is_empty() {
            &mut rules.jawless_weights
        } else if is_cyclops && !rules.cyclops_weights.is_empty() {
            &mut rules.cyclops_weights
        } else {
            &mut rules.normal_weights
        };
        // if changing the color of a style, create the weight table
        if rules.dye_style {
            let var_store = ReadonlyPrefixedStorage::new(storage, PREFIX_VARIANTS);
            // dye style potions always have a required list and always are for one category
            let cat_idx = rules.required[0].cat;
            let vars =
                may_load::<Vec<String>>(&var_store, &cat_idx.to_le_bytes())?.unwrap_or_default();
            let cur_var = image[cat_idx as usize] as usize;
            // split out the color of the style
            let (common, _) = vars[cur_var].rsplit_once(' ').ok_or_else(|| {
                StdError::generic_err("Can not find space delimited color in variant name")
            })?;
            *roll_tbl = vars
                .iter()
                .enumerate()
                .filter_map(|(i, n)| {
                    // create a weight for all variants that have the same style but do not include the current color
                    if i != cur_var && n.starts_with(common) {
                        Some(StoredTraitWeight {
                            layer: StoredLayerId {
                                category: cat_idx,
                                variant: i as u8,
                            },
                            weight: 1,
                        })
                    } else {
                        None
                    }
                })
                .collect::<Vec<StoredTraitWeight>>();
        } else {
            // if not creating the weight table, need to remove the traits this skull already has
            roll_tbl.retain(|t| t.layer.variant != image[t.layer.category as usize]);
        }
        if !roll_tbl.is_empty() {
            let winner = draw_winner::<StoredTraitWeight>(prng, roll_tbl);
            transmute_trait(storage, winner.layer, image, depends, trn_st)?;
        }
        // allowing an empty roll table to fall through in case some potions of a do all won't have an effect
        // but still want the others to work
    } else {
        let winner = draw_winner::<PotionWeight>(prng, &mut rules.potion_weights);
        potions.push(winner.idx);
    }

    Ok(())
}

/// Returns T
///
/// select a winner from a weight table
///
/// # Arguments
///
/// * `prng` - a mutable reference to the ContractPrng used to draw random selections
/// * `table` - weighted table slice
fn draw_winner<T: Weighted>(prng: &mut ContractPrng, table: &mut Vec<T>) -> T {
    let mut total_weight = 0u64;
    for t in table.iter() {
        total_weight += t.weight();
    }
    // randomly pick the winner
    let rdm = prng.next_u64();
    let winning_num = rdm % total_weight;
    let mut tally = 0u64;
    let mut winner = 0usize;
    for (i, t) in table.iter().enumerate() {
        // if the sum didn't panic on overflow, it can't happen here
        tally += t.weight();
        if tally > winning_num {
            winner = i;
            break;
        }
    }
    table.swap_remove(winner)
}

/// Returns StdResult<()>
///
/// give a skull a new trait, clearing out old dependencies and setting new ones
///
/// # Arguments
///
/// * `storage` - a reference to this contract's storage
/// * `new_trait` - category and variant of the new trait the skull should acquire
/// * `image` - a mutable reference to the current image array
/// * `depends` - list of traits that have multiple layers
/// * `trn_st` - a reference to the TransmuteState
fn transmute_trait(
    storage: &dyn Storage,
    new_trait: StoredLayerId,
    image: &mut [u8],
    depends: &[StoredDependencies],
    trn_st: &TransmuteState,
) -> StdResult<()> {
    // don't do anything if no change
    let old_var = image[new_trait.category as usize];
    if old_var != new_trait.variant {
        // check if the old trait had dependencies
        let old_lyr = StoredLayerId {
            category: new_trait.category,
            variant: old_var,
        };
        if let Some(old_dep) = depends.iter().find(|d| d.id == old_lyr) {
            for dep_lyr in old_dep.correlated.iter() {
                let big_cat = dep_lyr.category as usize;
                // set the dependency to None
                image[big_cat] = trn_st.nones[big_cat];
            }
        }
        // set the new trait
        image[new_trait.category as usize] = new_trait.variant;
        // also change the jaw if the skull material changed
        let big_jaw = trn_st.jawless.category as usize;
        if new_trait.category == trn_st.skull_idx && image[big_jaw] != trn_st.jawless.variant {
            let var_store = ReadonlyPrefixedStorage::new(storage, PREFIX_VARIANTS);
            let skulls = may_load::<Vec<String>>(&var_store, &trn_st.skull_idx.to_le_bytes())?
                .unwrap_or_default();
            let jaws = may_load::<Vec<String>>(&var_store, &trn_st.jawless.category.to_le_bytes())?
                .unwrap_or_default();
            image[big_jaw] = jaws
                .iter()
                .position(|j| *j == skulls[image[trn_st.skull_idx as usize] as usize])
                .ok_or_else(|| {
                    StdError::generic_err("Jaw variant name does not match skull variant name")
                })? as u8;
        }
        // check if the new trait has dependencies
        if let Some(new_dep) = depends.iter().find(|d| d.id == new_trait) {
            for dep_lyr in new_dep.correlated.iter() {
                image[dep_lyr.category as usize] = dep_lyr.variant;
            }
        }
    }
    Ok(())
}

/// Returns StdResult<Vec<u8>>
///
/// encode a potion name into its keyword indices
///
/// # Arguments
///
/// * `storage` - a reference to this contract's storage
/// * `name` - potion name to encode
/// * `keywords` - the list of name keywords split by position
fn encode_name(
    storage: &dyn Storage,
    name: &str,
    keywords: &mut Vec<Vec<String>>,
) -> StdResult<Vec<u8>> {
    // get the keywords if needed
    if keywords.is_empty() {
        *keywords = may_load::<Vec<Vec<String>>>(storage, NAME_KEYWORD_KEY)?.unwrap_or_default();
    }
    let split_name = name.split(' ').collect::<Vec<&str>>();
    split_name
        .iter()
        .enumerate()
        .map(|(i, n)| {
            keywords[i]
                .iter()
                .position(|k| k == n)
                .ok_or_else(|| {
                    StdError::generic_err(format!("Could not find {} in {}th keywords", n, i))
                })
                .map(|u| u as u8)
        })
        .collect::<StdResult<Vec<u8>>>()
}

/// Returns StdResult<String>
///
/// derive a potion name from its encoded form
///
/// # Arguments
///
/// * `storage` - a reference to this contract's storage
/// * `indices` - key word indices
/// * `keywords` - the list of name keywords split by position
fn derive_name(
    storage: &dyn Storage,
    indices: &[u8],
    keywords: &mut Vec<Vec<String>>,
) -> StdResult<String> {
    // get the keywords if needed
    if keywords.is_empty() {
        *keywords = may_load::<Vec<Vec<String>>>(storage, NAME_KEYWORD_KEY)?.unwrap_or_default();
    }
    let zipped = indices.iter().zip(keywords.iter());

    Ok(zipped
        .map(|(u, list)| (list[*u as usize]).as_str())
        .collect::<Vec<&str>>()
        .join(" "))
}

/// Returns Option<String>
///
/// checks if a skull is eligible for rewind
///
/// # Arguments
///
/// * `image` - ImageInfo of the skull attempting to rewind
fn can_rewind(image: &ImageInfo) -> Option<String> {
    if image.current.iter().any(|u| *u == 255) {
        Some("Only fully revealed skulls may be rewound".to_string())
    } else if image.previous.iter().any(|u| *u == 255) {
        Some("Skulls can not be rewound to an unrevealed state".to_string())
    } else if image.current == image.previous {
        Some("This skull has been rewound as far as it can".to_string())
    } else {
        None
    }
}

/// Returns StdResult<()>
///
/// update the build list and any potion rules affected by the change
///
/// # Arguments
///
/// * `storage` - a mutable reference to potion rule storage
/// * `build_list` - list of potions to use when building lists
/// * `cat_idx` - index of the category whose rep is changing
/// * `new_potion` - potion index of the new rep for this category
/// * `save_new` - true if the potion rule for the new potion should be updated and saved
fn change_cat_rep(
    storage: &mut dyn Storage,
    build_list: &mut [u16],
    cat_idx: usize,
    new_potion: u16,
    save_new: bool,
) -> StdResult<()> {
    let old_rep = build_list[cat_idx];
    if old_rep != new_potion {
        if old_rep != u16::MAX {
            // had a previous rep potion
            let old_rep_key = old_rep.to_le_bytes();
            if let Some(mut old_rep_rule) = may_load::<StoredPotionRules>(storage, &old_rep_key)? {
                // save that it is no longer the rep
                old_rep_rule.cat_rep = false;
                save(storage, &old_rep_key, &old_rep_rule)?;
            }
        }
        if save_new && new_potion != u16::MAX {
            // need to update the new potion's rule
            let new_potion_key = new_potion.to_le_bytes();
            let mut new_potion_rule = may_load::<StoredPotionRules>(storage, &new_potion_key)?
                .ok_or_else(|| {
                    StdError::generic_err(format!("{} is not a valid potion index", new_potion))
                })?;
            new_potion_rule.cat_rep = true;
            save(storage, &new_potion_key, &new_potion_rule)?;
        }
        build_list[cat_idx] = new_potion;
    }
    Ok(())
}

// struct used to randomize recipe length
#[derive(Clone)]
pub struct LengthAdj {
    // adjustment amount
    pub adj: i8,
    // draw weight for this adjustment
    pub weight: u64,
}

impl Weighted for LengthAdj {
    fn weight(&self) -> u64 {
        self.weight
    }
}

// struct used to randomize recipe ingredients
pub struct IngredientWeight {
    // ingredient index
    pub idx: usize,
    // draw weight for this ingredient
    pub weight: u64,
}

impl Weighted for IngredientWeight {
    fn weight(&self) -> u64 {
        self.weight
    }
}

/// Returns StdResult<u8>
///
/// pick a random ingredient based on rarity and usage
///
/// # Arguments
///
/// * `target_rarity` - target average rarity for recipe
/// * `usage` - running counts of ingredient selection
/// * `rarities` - commonality scores for all ingredients
/// * `rarity_sum` - running sum of all rarities selected in this recipe
/// * `ordinal` - how many ingredients have already been selected in this recipe
/// * `stressor` - increasing severity for rarity selection based on how many spots are left
/// * `rng` - a mutable reference to the ContractPrng
fn draw_ingredient(
    target_rarity: u8,
    usage: &mut [u32],
    rarities: &[u8],
    rarity_sum: &mut u64,
    ordinal: u64,
    stressor: u64,
    rng: &mut ContractPrng,
) -> u8 {
    // get least used count
    let min_cnt = usage.iter().min().unwrap();
    let zip_stats = rarities.iter().zip(usage.iter());
    let target_sum = target_rarity as u64 * ordinal;
    let current_diff = target_sum as i64 - *rarity_sum as i64;
    // weight rarity importance higher when you are further away from target and when you have fewer ingredients left
    // to balance it out
    let rarity_factor =
        (current_diff.unsigned_abs() + 1) * CALC_RARITY_FACTOR * stressor * stressor;
    let mut max_pen = 0u64;
    let mut min_pen = u64::MAX;
    let total_pens = zip_stats
        .map(|(r, c)| {
            // new difference if this ingredient is picked
            let hypo_diff = current_diff + target_rarity as i64 - *r as i64;
            let rarity_penalty = hypo_diff.unsigned_abs() * rarity_factor;
            // only use usage penalty for certain targets
            let usage_penalty = if (MIN_USAGE_PEN_LIM..MAX_USAGE_PEN_LIM).contains(&target_rarity) {
                (*c - min_cnt) as u64 * USAGE_FACTOR * stressor * stressor
            } else {
                0
            };
            let total = rarity_penalty + usage_penalty;
            if total > max_pen {
                max_pen = total;
            }
            if total < min_pen {
                min_pen = total;
            }
            total
        })
        .collect::<Vec<u64>>();

    // still give the lowest weight some chance based on 5% of the spread from low to high
    let booster = ((max_pen - min_pen) * 5 / 100) + 1;
    // build the weight table
    let mut table = total_pens
        .iter()
        .enumerate()
        .map(|(i, u)| IngredientWeight {
            idx: i,
            weight: max_pen - *u + booster,
        })
        .collect::<Vec<IngredientWeight>>();
    // select the winner
    let winner = draw_winner::<IngredientWeight>(rng, &mut table);
    // increment the usage count for the winner
    usage[winner.idx] += 1;
    // include winner rarity in running rarity sum
    *rarity_sum += rarities[winner.idx] as u64;

    winner.idx as u8
}

/// Returns StdResult<Vec<u8>>
///
/// generate a unique recipe
///
/// # Arguments
///
/// * `storage` - a mutable reference to recipe to name storage
/// * `len_adj` - recipe length adjustments and weights
/// * `rec_gen` - stats needed for recipe generation
/// * `rng` - a mutable reference to the ContractPrng
/// * `name` - encoded name of the potion which needs a recipe
/// * `target_rarity` - target average rarity for the ingredients in the recipe
/// * `complexity` - base recipe length desired
fn gen_recipe(
    storage: &mut dyn Storage,
    len_adj: &[LengthAdj],
    rec_gen: &mut RecipeGen,
    rng: &mut ContractPrng,
    name: &Vec<u8>,
    target_rarity: u8,
    complexity: i8,
) -> StdResult<Vec<u8>> {
    // only draw from lengths that are within limits
    let mut len_table = len_adj
        .iter()
        .filter_map(|la| {
            if (MIN_RECIPE_LEN..MAX_RECIPE_LEN + 1).contains(&(complexity + la.adj)) {
                Some(la.clone())
            } else {
                None
            }
        })
        .collect::<Vec<LengthAdj>>();
    let len = complexity + draw_winner::<LengthAdj>(rng, &mut len_table).adj;
    let big_len = len as u64;
    let stressor = (MAX_RECIPE_LEN + 1 - len) as u64;
    // create threshold for discarding the recipe if too far from target
    let threshold = if target_rarity < WHEN_THRESHOLD {
        RARITY_AVG_THRESHOLD as u64 * big_len
    } else {
        u64::MAX
    };
    let target_tally = target_rarity as u64 * big_len;
    let mut rarity_tally: u64;
    let mut recipe: Vec<u8>;
    loop {
        rarity_tally = 0;
        recipe = Vec::new();
        // create the recipe
        for i in 0..big_len {
            recipe.push(draw_ingredient(
                target_rarity,
                &mut rec_gen.usage,
                &rec_gen.rarities,
                &mut rarity_tally,
                i,
                stressor + i,
                rng,
            ));
        }
        let rarity_diff = if rarity_tally > target_tally {
            rarity_tally - target_tally
        } else {
            target_tally - rarity_tally
        };
        // because the algo tries harder to push back towards the target as we
        // get closer to the end, let's just give it a shuffle
        let mut temp = Vec::new();
        while !recipe.is_empty() {
            temp.push(recipe.swap_remove((rng.next_u64() % (recipe.len() as u64)) as usize));
        }
        recipe = temp;
        let recipe_key = recipe.as_slice();
        // keep if close enough to the target and the recipe is unique
        if rarity_diff < threshold && may_load::<Vec<u8>>(storage, recipe_key)?.is_none() {
            save(storage, recipe_key, name)?;
            break;
        }
        // discarded so remove the counts
        for ing in recipe.iter() {
            rec_gen.usage[*ing as usize] -= 1;
        }
    }
    Ok(recipe)
}

///////////////////////////////////// Migrate //////////////////////////////////////
/// Returns StdResult<Response>
///
/// gives crate contracts the new code hash
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `msg` - Empty migrate msg
#[entry_point]
pub fn migrate(deps: DepsMut, env: Env, _msg: Empty) -> StdResult<Response> {
    let raw_crates: Vec<StoreContractInfo> = load(deps.storage, CRATES_KEY)?;
    let mut messages: Vec<CosmosMsg> = Vec::new();
    for crat in raw_crates.into_iter() {
        let hmn = crat.into_humanized(deps.api)?;
        messages.push(
            Snip721HandleMsg::RegisterReceiveNft {
                code_hash: env.contract.code_hash.clone(),
                also_implements_batch_receive_nft: true,
            }
            .to_cosmos_msg(hmn.code_hash, hmn.address, None)?,
        );
    }
    let raw_potions =
        may_load::<Vec<StoreContractInfo>>(deps.storage, POTION_721_KEY)?.unwrap_or_default();
    save(deps.storage, POTION_721_KEY, &raw_potions)?;
    for ptn in raw_potions.into_iter() {
        let hmn = ptn.into_humanized(deps.api)?;
        messages.push(
            Snip721HandleMsg::RegisterReceiveNft {
                code_hash: env.contract.code_hash.clone(),
                also_implements_batch_receive_nft: true,
            }
            .to_cosmos_msg(hmn.code_hash, hmn.address, None)?,
        );
    }
    // migrate to new alchemy state format

    /// old alchemy state
    #[derive(Deserialize)]
    pub struct OldAlchemyState {
        /// true if alchemy is halted
        pub halt: bool,
        /// StoredLayerId for cyclops
        pub cyclops: StoredLayerId,
        /// StoredLayerId for jawless
        pub jawless: StoredLayerId,
    }

    let old_st: OldAlchemyState = load(deps.storage, ALCHEMY_STATE_KEY)?;
    let new_st = AlchemyState {
        halt: old_st.halt,
        potion_cnt: 0,
        found_cnt: 0,
        disabled: Vec::new(),
        ptn_img_total: 0,
        img_pool_cnt: 0,
    };
    save(deps.storage, ALCHEMY_STATE_KEY, &new_st)?;
    // init the transmutation state
    let trn_st = TransmuteState {
        skip: Vec::new(),
        nones: Vec::new(),
        jaw_only: Vec::new(),
        build_list: Vec::new(),
        cyclops: old_st.cyclops,
        jawless: old_st.jawless,
        skull_idx: 2,
    };
    save(deps.storage, TRANSMUTE_STATE_KEY, &trn_st)?;
    // init recipe generation info
    let rec_gen = RecipeGen {
        rarities: Vec::new(),
        usage: Vec::new(),
    };
    save(deps.storage, RECIPE_GEN_KEY, &rec_gen)?;

    Ok(Response::new().add_messages(messages))
}
