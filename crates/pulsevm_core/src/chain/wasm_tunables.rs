//! Runtime enforcement of the EOSIO linear-memory and table ceilings.
//!
//! [`pulsevm_wasm_validation`] rejects a module that *declares* a memory or
//! table above the limit, but a conforming module normally declares no
//! `maximum` at all -- `(memory 1)` is what every real toolchain emits. For
//! those, validation has nothing to reject and the ceiling is whatever the
//! runtime allows, which for stock wasmer is `Pages::max_value()`: **65 536
//! pages, or 4 GiB**, reachable with a single `memory.grow` costing 1 000
//! metering points.
//!
//! That mattered for more than memory footprint. It set the per-instruction
//! ceiling for `memory.fill`/`memory.copy` (one instruction, one bulk `memset`
//! over the whole memory), the retained size of every instance held in the
//! warm-store pool, and the size of the host-side buffers that host functions
//! allocate from a guest-supplied length.
//!
//! [`LimitingTunables`] clamps both dimensions at instantiation, independently
//! of what the module declares, so the bound holds even if the validator is
//! bypassed -- for example by code already in state from genesis or a snapshot
//! restore, which is never re-validated.

use std::ptr::NonNull;

use wasmer::{
    MemoryError,
    MemoryStyle,
    MemoryType,
    Pages,
    TableStyle,
    TableType,
    sys::{
        BaseTunables,
        Tunables,
        vm::{
            VMMemory,
            VMMemoryDefinition,
            VMTable,
            VMTableDefinition,
        },
    },
};

/// Wraps a base [`Tunables`], clamping every memory and table it creates.
pub struct LimitingTunables<T: Tunables> {
    base: T,
    /// Hard ceiling on linear-memory pages, applied whether or not the module
    /// declares a maximum.
    max_pages: Pages,
    /// Hard ceiling on table elements, likewise.
    max_table_elements: u32,
}

impl<T: Tunables> LimitingTunables<T> {
    pub fn new(base: T, max_pages: Pages, max_table_elements: u32) -> Self {
        Self {
            base,
            max_pages,
            max_table_elements,
        }
    }

    /// The memory type as it will actually be instantiated: the declared
    /// maximum, lowered to our ceiling, and always present.
    fn clamped_memory(&self, memory: &MemoryType) -> Result<MemoryType, MemoryError> {
        if memory.minimum > self.max_pages {
            return Err(MemoryError::Generic(format!(
                "memory minimum of {} pages exceeds the {} page limit",
                memory.minimum.0, self.max_pages.0
            )));
        }
        let maximum = match memory.maximum {
            Some(declared) if declared < self.max_pages => declared,
            _ => self.max_pages,
        };
        let mut clamped = *memory;
        clamped.maximum = Some(maximum);
        Ok(clamped)
    }

    /// As above, for tables.
    fn clamped_table(&self, table: &TableType) -> Result<TableType, String> {
        if table.minimum > self.max_table_elements {
            return Err(format!(
                "table minimum of {} elements exceeds the {} element limit",
                table.minimum, self.max_table_elements
            ));
        }
        let maximum = match table.maximum {
            Some(declared) if declared < self.max_table_elements => declared,
            _ => self.max_table_elements,
        };
        let mut clamped = *table;
        clamped.maximum = Some(maximum);
        Ok(clamped)
    }
}

impl<T: Tunables> Tunables for LimitingTunables<T> {
    // The *style* must be derived from the clamped type too. Deriving it from
    // the declared type would size the reservation and the bounds-check strategy
    // for a memory the instance is never allowed to reach.
    fn memory_style(&self, memory: &MemoryType) -> MemoryStyle {
        let clamped = self.clamped_memory(memory).unwrap_or(*memory);
        self.base.memory_style(&clamped)
    }

    fn table_style(&self, table: &TableType) -> TableStyle {
        let clamped = self.clamped_table(table).unwrap_or(*table);
        self.base.table_style(&clamped)
    }

    fn create_host_memory(
        &self,
        ty: &MemoryType,
        style: &MemoryStyle,
    ) -> Result<VMMemory, MemoryError> {
        self.base
            .create_host_memory(&self.clamped_memory(ty)?, style)
    }

    unsafe fn create_vm_memory(
        &self,
        ty: &MemoryType,
        style: &MemoryStyle,
        vm_definition_location: NonNull<VMMemoryDefinition>,
    ) -> Result<VMMemory, MemoryError> {
        unsafe {
            self.base
                .create_vm_memory(&self.clamped_memory(ty)?, style, vm_definition_location)
        }
    }

    fn create_host_table(&self, ty: &TableType, style: &TableStyle) -> Result<VMTable, String> {
        self.base.create_host_table(&self.clamped_table(ty)?, style)
    }

    unsafe fn create_vm_table(
        &self,
        ty: &TableType,
        style: &TableStyle,
        vm_definition_location: NonNull<VMTableDefinition>,
    ) -> Result<VMTable, String> {
        unsafe {
            self.base
                .create_vm_table(&self.clamped_table(ty)?, style, vm_definition_location)
        }
    }
}

/// The EOSIO ceiling: 528 pages (33 MiB), matching
/// `pulsevm_wasm_validation::constraints::MAXIMUM_LINEAR_MEMORY`.
pub const MAX_LINEAR_MEMORY_PAGES: u32 =
    (pulsevm_wasm_validation::constraints::MAXIMUM_LINEAR_MEMORY
        / pulsevm_wasm_validation::constraints::WASM_PAGE_SIZE) as u32;

/// The EOSIO ceiling on indirect-call table elements, matching
/// `pulsevm_wasm_validation::constraints::MAXIMUM_TABLE_ELEMENTS`.
pub const MAX_TABLE_ELEMENTS: u32 =
    pulsevm_wasm_validation::constraints::MAXIMUM_TABLE_ELEMENTS as u32;

/// The tunables every engine in this VM runs with.
pub fn deterministic_tunables(target: &wasmer::sys::Target) -> LimitingTunables<BaseTunables> {
    LimitingTunables::new(
        BaseTunables::for_target(target),
        Pages(MAX_LINEAR_MEMORY_PAGES),
        MAX_TABLE_ELEMENTS,
    )
}
