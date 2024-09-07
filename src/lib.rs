use std::collections::{HashMap, HashSet};
use wasm_bindgen::prelude::*;
use web_sys::console;

/// A highly optimized ERC1155 implementation in Rust for WebAssembly (WASM).
#[wasm_bindgen]
pub struct ERC1155 {
    access_control: AccessControl,
    balances: HashMap<(String, u32), u64>,  // (User, TokenID) -> Balance
    approvals: HashMap<String, HashMap<String, bool>>, // User -> (Approved User -> Approval Status)
    reentrancy_guard: ReentrancyGuard,
}

/// Reentrancy guard to prevent reentrancy attacks.
pub struct ReentrancyGuard {
    is_locked: bool,
}

impl ReentrancyGuard {
    /// Creates a new reentrancy guard.
    pub fn new() -> Self {
        Self { is_locked: false }
    }

    /// Locks the guard, preventing reentrant calls.
    pub fn enter(&mut self) -> Result<(), String> {
        if self.is_locked {
            return Err("Reentrancy detected.".into());
        }
        self.is_locked = true;
        Ok(())
    }

    /// Unlocks the guard, allowing further function execution.
    pub fn exit(&mut self) {
        self.is_locked = false;
    }
}

/// Structure for managing access control (owner and admin rights).
pub struct AccessControl {
    owner: String,
    admins: HashSet<String>,
}

impl AccessControl {
    /// Initializes a new access control structure with the contract owner.
    pub fn new(owner: String) -> Self {
        Self {
            owner,
            admins: HashSet::new(),
        }
    }

    /// Checks if the caller is the owner.
    pub fn is_owner(&self, caller: &str) -> bool {
        self.owner == caller
    }

    /// Checks if the caller is an admin.
    pub fn is_admin(&self, caller: &str) -> bool {
        self.admins.contains(caller)
    }

    /// Adds a new admin to the contract (only the owner can add admins).
    pub fn add_admin(&mut self, caller: &str, new_admin: &str) -> Result<(), String> {
        if !self.is_owner(caller) {
            return Err("Only the owner can add admins.".into());
        }
        self.admins.insert(new_admin.to_string());
        Ok(())
    }
}

#[wasm_bindgen]
impl ERC1155 {
    /// Initializes a new ERC1155 contract with the owner.
    /// # Parameters
    /// - `owner`: The initial owner of the contract.
    #[wasm_bindgen(constructor)]
    pub fn new(owner: &str) -> ERC1155 {
        console::log_1(&format!("ERC1155 initialized with owner: {}", owner).into());
        ERC1155 {
            access_control: AccessControl::new(owner.to_string()),
            balances: HashMap::new(),
            approvals: HashMap::new(),
            reentrancy_guard: ReentrancyGuard::new(),
        }
    }

    /// Mints new tokens for a given `token_id` (only admins can mint).
    /// # Parameters
    /// - `caller`: The address calling the function (must be an admin).
    /// - `token_id`: The ID of the token to mint.
    /// - `amount`: The number of tokens to mint.
    pub fn mint(&mut self, caller: &str, token_id: u32, amount: u64) -> Result<(), String> {
        if !self.access_control.is_admin(caller) {
            console::log_1(&format!("Mint failed: {} is not an admin", caller).into());
            return Err("Caller is not authorized to mint tokens.".into());
        }

        self.reentrancy_guard.enter()?; // Reentrancy protection

        let balance = self.balances.entry((caller.to_string(), token_id)).or_insert(0);
        *balance += amount;

        console::log_1(&format!("Minted {} tokens of ID {} to {}", amount, token_id, caller).into());
        self.reentrancy_guard.exit(); // Reentrancy protection exit

        Ok(())
    }

    /// Transfers tokens to another user.
    /// # Parameters
    /// - `caller`: The address initiating the transfer (must be owner or approved).
    /// - `to`: The recipient of the tokens.
    /// - `token_id`: The ID of the token being transferred.
    /// - `amount`: The number of tokens to transfer.
    pub fn transfer(&mut self, caller: &str, to: &str, token_id: u32, amount: u64) -> Result<(), String> {
        // Check if the caller is the owner or approved to transfer
        if !self.is_approved(caller, token_id) && !self.access_control.is_owner(caller) {
            console::log_1(&format!("Transfer failed: {} is not approved or the owner.", caller).into());
            return Err("Caller is not authorized to transfer.".into());
        }

        // Transfer logic
        let balance = self.balances.entry((caller.to_string(), token_id)).or_insert(0);
        if *balance < amount {
            return Err("Insufficient balance.".into());
        }
        *balance -= amount;
        let recipient_balance = self.balances.entry((to.to_string(), token_id)).or_insert(0);
        *recipient_balance += amount;

        console::log_1(&format!("Transferred {} tokens of ID {} from {} to {}", amount, token_id, caller, to).into());
        Ok(())
    }

    /// Approves another user to transfer tokens on behalf of the caller.
    pub fn approve(&mut self, caller: &str, approved: &str, token_id: u32) -> Result<(), String> {
        let approval_entry = self.approvals.entry(caller.to_string()).or_insert_with(HashMap::new);
        approval_entry.insert(approved.to_string(), true);

        console::log_1(&format!("Approval set for {} to transfer token ID {} by {}", approved, token_id, caller).into());
        Ok(())
    }

    /// Returns the balance of tokens for a specific user and token ID.
    pub fn balance_of(&self, owner: &str, token_id: u32) -> u64 {
        *self.balances.get(&(owner.to_string(), token_id)).unwrap_or(&0)
    }

    /// Adds a new admin to the contract (only the owner can add admins).
    pub fn add_admin(&mut self, caller: &str, new_admin: &str) -> Result<(), String> {
        self.access_control.add_admin(caller, new_admin)
    }

    /// Transfers ownership of the contract (only the current owner can transfer).
    pub fn transfer_ownership(&mut self, caller: &str, new_owner: &str) -> Result<(), String> {
        if self.access_control.is_owner(caller) {
            self.access_control = AccessControl::new(new_owner.to_string());
            console::log_1(&format!("Ownership transferred to {}", new_owner).into());
            Ok(())
        } else {
            Err("Caller is not authorized to transfer ownership.".into())
        }
    }

    /// Internal function to check if the caller is approved to transfer a token.
    fn is_approved(&self, caller: &str, token_id: u32) -> bool {
        if let Some(approval_map) = self.approvals.get(caller) {
            return *approval_map.get(&token_id.to_string()).unwrap_or(&false);
        }
        false
    }
}
