// Copyright (C) 2025 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use monad_event_ring::{
    ffi::{monad_event_content_type, monad_event_record_error, MONAD_EVENT_CONTENT_TYPE_EXEC},
    EventDecoder, EventDescriptorInfo,
};

use self::bytes::{ref_from_bytes, ref_from_bytes_with_trailing};

static MONAD_TRACER_LOG: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

fn monad_tracer_log_enabled() -> bool {
    *MONAD_TRACER_LOG.get_or_init(|| std::env::var_os("MONAD_TRACER_LOG").is_some())
}

macro_rules! tracer_log {
    ($fmt:literal $(, $arg:expr)*) => {
        if monad_tracer_log_enabled() {
            eprintln!(concat!("[tracer] ", $fmt) $(, $arg)*);
        }
    };
}

fn txn_str(txn_idx: Option<usize>) -> String {
    txn_idx.map_or_else(|| "block".to_string(), |i| i.to_string())
}

fn u256_hex(limbs: &[u64; 4]) -> String {
    let mut b = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        b[24 - i * 8..32 - i * 8].copy_from_slice(&limb.to_be_bytes());
    }
    hex::encode(b)
}

use crate::ffi::{
    self, g_monad_exec_event_schema_hash, monad_exec_account_access,
    monad_exec_account_access_list_header, monad_exec_block_end, monad_exec_block_finalized,
    monad_exec_block_qc, monad_exec_block_reject, monad_exec_block_start,
    monad_exec_block_system_call_end, monad_exec_block_system_call_start,
    monad_exec_block_verified, monad_exec_evm_error, monad_exec_storage_access,
    monad_exec_txn_access_list_entry, monad_exec_txn_auth_list_entry, monad_exec_txn_call_frame,
    monad_exec_txn_evm_output, monad_exec_txn_header_start, monad_exec_txn_log,
    monad_exec_txn_reject,
};

mod bytes;

/// Marker type that implements [`EventDecoder`] for monad execution events.
#[derive(Debug)]
pub struct ExecEventDecoder;

/// Owned rust enum for monad execution events.
///
/// This type uses the bindgen generated monad-execution C types to enable efficient memcpys of
/// event ring payloads.
///
/// See [`ExecEventRef`] for the zero-copy ref version.
#[allow(missing_docs)]
#[derive(Clone, Debug, strum::EnumDiscriminants)]
#[strum_discriminants(name(ExecEventType), allow(missing_docs))]
pub enum ExecEvent {
    RecordError(monad_event_record_error),
    BlockStart(monad_exec_block_start),
    BlockReject(monad_exec_block_reject),
    BlockPerfEvmEnter,
    BlockPerfEvmExit,
    BlockEnd(monad_exec_block_end),
    BlockQC(monad_exec_block_qc),
    BlockFinalized(monad_exec_block_finalized),
    BlockVerified(monad_exec_block_verified),
    TxnHeaderStart {
        txn_index: usize,
        txn_header_start: monad_exec_txn_header_start,
        data_bytes: Box<[u8]>,
        blob_bytes: Box<[u8]>,
    },
    TxnAccessListEntry {
        txn_index: usize,
        txn_access_list_entry: monad_exec_txn_access_list_entry,
        storage_key_bytes: Box<[u8]>,
    },
    TxnAuthListEntry {
        txn_index: usize,
        txn_auth_list_entry: monad_exec_txn_auth_list_entry,
    },
    TxnHeaderEnd,
    TxnReject {
        txn_index: usize,
        reject: monad_exec_txn_reject,
    },
    TxnPerfEvmEnter,
    TxnPerfEvmExit,
    TxnEvmOutput {
        txn_index: usize,
        output: monad_exec_txn_evm_output,
    },
    TxnLog {
        txn_index: usize,
        txn_log: monad_exec_txn_log,
        topic_bytes: Box<[u8]>,
        data_bytes: Box<[u8]>,
    },
    TxnCallFrame {
        txn_index: usize,
        txn_call_frame: monad_exec_txn_call_frame,
        input_bytes: Box<[u8]>,
        return_bytes: Box<[u8]>,
    },
    TxnEnd,
    AccountAccessListHeader(monad_exec_account_access_list_header),
    AccountAccess(monad_exec_account_access),
    StorageAccess(monad_exec_storage_access),
    EvmError(monad_exec_evm_error),
    BlockSystemCallStart {
        system_call_start: monad_exec_block_system_call_start,
        input_bytes: Box<[u8]>,
    },
    BlockSystemCallEnd {
        system_call_end: monad_exec_block_system_call_end,
        return_bytes: Box<[u8]>,
    },
}

/// Ref rust enum for monad execution events.
///
/// This enum should only be used with the zero-copy event ring API to enable zero-copy access to
/// event ring payloads.
///
/// See [`ExecEvent`] for the owned version.
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug)]
pub enum ExecEventRef<'ring> {
    RecordError(&'ring monad_event_record_error),
    BlockStart(&'ring monad_exec_block_start),
    BlockReject(&'ring monad_exec_block_reject),
    BlockPerfEvmEnter,
    BlockPerfEvmExit,
    BlockEnd(&'ring monad_exec_block_end),
    BlockQC(&'ring monad_exec_block_qc),
    BlockFinalized(&'ring monad_exec_block_finalized),
    BlockVerified(&'ring monad_exec_block_verified),
    TxnHeaderStart {
        txn_index: usize,
        txn_header_start: &'ring monad_exec_txn_header_start,
        data_bytes: &'ring [u8],
        blob_bytes: &'ring [u8],
    },
    TxnAccessListEntry {
        txn_index: usize,
        txn_access_list_entry: &'ring monad_exec_txn_access_list_entry,
        storage_key_bytes: &'ring [u8],
    },
    TxnAuthListEntry {
        txn_index: usize,
        txn_auth_list_entry: &'ring monad_exec_txn_auth_list_entry,
    },
    TxnHeaderEnd,
    TxnReject {
        txn_index: usize,
        reject: &'ring monad_exec_txn_reject,
    },
    TxnPerfEvmEnter,
    TxnPerfEvmExit,
    TxnEvmOutput {
        txn_index: usize,
        output: &'ring monad_exec_txn_evm_output,
    },
    TxnLog {
        txn_index: usize,
        txn_log: &'ring monad_exec_txn_log,
        topic_bytes: &'ring [u8],
        data_bytes: &'ring [u8],
    },
    TxnCallFrame {
        txn_index: usize,
        txn_call_frame: &'ring monad_exec_txn_call_frame,
        input_bytes: &'ring [u8],
        return_bytes: &'ring [u8],
    },
    TxnEnd,
    AccountAccessListHeader(&'ring monad_exec_account_access_list_header),
    AccountAccess(&'ring monad_exec_account_access),
    StorageAccess(&'ring monad_exec_storage_access),
    EvmError(&'ring monad_exec_evm_error),
    BlockSystemCallStart {
        system_call_start: &'ring monad_exec_block_system_call_start,
        input_bytes: &'ring [u8],
    },
    BlockSystemCallEnd {
        system_call_end: &'ring monad_exec_block_system_call_end,
        return_bytes: &'ring [u8],
    },
}

impl ExecEventType {
    pub(crate) fn as_c_event_type(self) -> crate::ffi::monad_exec_event_type {
        match self {
            ExecEventType::RecordError => ffi::MONAD_EXEC_RECORD_ERROR,
            ExecEventType::BlockStart => ffi::MONAD_EXEC_BLOCK_START,
            ExecEventType::BlockReject => ffi::MONAD_EXEC_BLOCK_REJECT,
            ExecEventType::BlockPerfEvmEnter => ffi::MONAD_EXEC_BLOCK_PERF_EVM_ENTER,
            ExecEventType::BlockPerfEvmExit => ffi::MONAD_EXEC_BLOCK_PERF_EVM_EXIT,
            ExecEventType::BlockEnd => ffi::MONAD_EXEC_BLOCK_END,
            ExecEventType::BlockQC => ffi::MONAD_EXEC_BLOCK_QC,
            ExecEventType::BlockFinalized => ffi::MONAD_EXEC_BLOCK_FINALIZED,
            ExecEventType::BlockVerified => ffi::MONAD_EXEC_BLOCK_VERIFIED,
            ExecEventType::TxnHeaderStart => ffi::MONAD_EXEC_TXN_HEADER_START,
            ExecEventType::TxnAccessListEntry => ffi::MONAD_EXEC_TXN_ACCESS_LIST_ENTRY,
            ExecEventType::TxnAuthListEntry => ffi::MONAD_EXEC_TXN_AUTH_LIST_ENTRY,
            ExecEventType::TxnHeaderEnd => ffi::MONAD_EXEC_TXN_HEADER_END,
            ExecEventType::TxnReject => ffi::MONAD_EXEC_TXN_REJECT,
            ExecEventType::TxnPerfEvmEnter => ffi::MONAD_EXEC_TXN_PERF_EVM_ENTER,
            ExecEventType::TxnPerfEvmExit => ffi::MONAD_EXEC_TXN_PERF_EVM_EXIT,
            ExecEventType::TxnEvmOutput => ffi::MONAD_EXEC_TXN_EVM_OUTPUT,
            ExecEventType::TxnLog => ffi::MONAD_EXEC_TXN_LOG,
            ExecEventType::TxnCallFrame => ffi::MONAD_EXEC_TXN_CALL_FRAME,
            ExecEventType::TxnEnd => ffi::MONAD_EXEC_TXN_END,
            ExecEventType::AccountAccessListHeader => ffi::MONAD_EXEC_ACCOUNT_ACCESS_LIST_HEADER,
            ExecEventType::AccountAccess => ffi::MONAD_EXEC_ACCOUNT_ACCESS,
            ExecEventType::StorageAccess => ffi::MONAD_EXEC_STORAGE_ACCESS,
            ExecEventType::EvmError => ffi::MONAD_EXEC_EVM_ERROR,
            ExecEventType::BlockSystemCallStart => ffi::MONAD_EXEC_BLOCK_SYSTEM_CALL_START,
            ExecEventType::BlockSystemCallEnd => ffi::MONAD_EXEC_BLOCK_SYSTEM_CALL_END,
        }
    }
}

impl<'ring> ExecEventRef<'ring> {
    /// Converts the [`ExecEventRef`] to its owned variant [`ExecEvent`].
    pub fn into_owned(self) -> ExecEvent {
        match self {
            Self::RecordError(record_error) => ExecEvent::RecordError(*record_error),
            Self::BlockStart(block_start) => ExecEvent::BlockStart(*block_start),
            Self::BlockReject(block_reject) => ExecEvent::BlockReject(*block_reject),
            Self::BlockPerfEvmEnter => ExecEvent::BlockPerfEvmEnter,
            Self::BlockPerfEvmExit => ExecEvent::BlockPerfEvmExit,
            Self::BlockEnd(block_end) => ExecEvent::BlockEnd(*block_end),
            Self::BlockQC(block_qc) => ExecEvent::BlockQC(*block_qc),
            Self::BlockFinalized(block_finalized) => ExecEvent::BlockFinalized(*block_finalized),
            Self::BlockVerified(block_verified) => ExecEvent::BlockVerified(*block_verified),
            Self::TxnHeaderStart {
                txn_index,
                txn_header_start: txn_start,
                data_bytes,
                blob_bytes: blobs,
            } => ExecEvent::TxnHeaderStart {
                txn_index,
                txn_header_start: *txn_start,
                data_bytes: data_bytes.to_vec().into_boxed_slice(),
                blob_bytes: blobs.to_vec().into_boxed_slice(),
            },
            Self::TxnAccessListEntry {
                txn_index,
                txn_access_list_entry,
                storage_key_bytes: storage_keys,
            } => ExecEvent::TxnAccessListEntry {
                txn_index,
                txn_access_list_entry: *txn_access_list_entry,
                storage_key_bytes: storage_keys.to_vec().into_boxed_slice(),
            },
            Self::TxnAuthListEntry {
                txn_index,
                txn_auth_list_entry,
            } => ExecEvent::TxnAuthListEntry {
                txn_index,
                txn_auth_list_entry: *txn_auth_list_entry,
            },
            Self::TxnHeaderEnd => ExecEvent::TxnHeaderEnd,
            Self::TxnReject { txn_index, reject } => ExecEvent::TxnReject {
                txn_index,
                reject: *reject,
            },
            Self::TxnPerfEvmEnter => ExecEvent::TxnPerfEvmEnter,
            Self::TxnPerfEvmExit => ExecEvent::TxnPerfEvmExit,
            Self::TxnEvmOutput { txn_index, output } => ExecEvent::TxnEvmOutput {
                txn_index,
                output: *output,
            },
            Self::TxnLog {
                txn_index,
                txn_log,
                topic_bytes,
                data_bytes,
            } => ExecEvent::TxnLog {
                txn_index,
                txn_log: *txn_log,
                topic_bytes: topic_bytes.to_vec().into_boxed_slice(),
                data_bytes: data_bytes.to_vec().into_boxed_slice(),
            },
            Self::TxnCallFrame {
                txn_index,
                txn_call_frame,
                input_bytes,
                return_bytes,
            } => ExecEvent::TxnCallFrame {
                txn_index,
                txn_call_frame: *txn_call_frame,
                input_bytes: input_bytes.to_vec().into_boxed_slice(),
                return_bytes: return_bytes.to_vec().into_boxed_slice(),
            },
            Self::TxnEnd => ExecEvent::TxnEnd,
            Self::AccountAccessListHeader(account_access_list_header) => {
                ExecEvent::AccountAccessListHeader(*account_access_list_header)
            }
            Self::AccountAccess(account_access) => ExecEvent::AccountAccess(*account_access),
            Self::StorageAccess(storage_access) => ExecEvent::StorageAccess(*storage_access),
            Self::EvmError(evm_error) => ExecEvent::EvmError(*evm_error),
            Self::BlockSystemCallStart { system_call_start, input_bytes } => {
                ExecEvent::BlockSystemCallStart {
                    system_call_start: *system_call_start,
                    input_bytes: input_bytes.to_vec().into_boxed_slice(),
                }
            }
            Self::BlockSystemCallEnd { system_call_end, return_bytes } => {
                ExecEvent::BlockSystemCallEnd {
                    system_call_end: *system_call_end,
                    return_bytes: return_bytes.to_vec().into_boxed_slice(),
                }
            }
        }
    }
}

/// Flow info for execution events.
pub struct ExecEventRingFlowInfo {
    block_seqno: u64,
    txn_idx: Option<usize>,
    account_idx: u64,
}

impl EventDecoder for ExecEventDecoder {
    fn ring_content_ctype() -> monad_event_content_type {
        MONAD_EVENT_CONTENT_TYPE_EXEC
    }

    fn ring_schema_hash() -> &'static [u8; 32] {
        unsafe { &g_monad_exec_event_schema_hash }
    }

    type FlowInfo = ExecEventRingFlowInfo;

    fn transmute_flow_info(user: [u64; 4]) -> Self::FlowInfo {
        Self::FlowInfo {
            block_seqno: user[ffi::MONAD_FLOW_BLOCK_SEQNO as usize],
            txn_idx: user[ffi::MONAD_FLOW_TXN_ID as usize]
                .checked_sub(1)
                .map(|txn_idx| txn_idx.try_into().unwrap()),
            account_idx: user[ffi::MONAD_FLOW_ACCOUNT_INDEX as usize],
        }
    }

    type Event = ExecEvent;
    type EventRef<'ring> = ExecEventRef<'ring>;

    fn raw_to_event_ref<'ring>(
        info: EventDescriptorInfo<Self>,
        bytes: &'ring [u8],
    ) -> Self::EventRef<'ring> {
        match info.event_type {
            ffi::MONAD_EXEC_NONE => {
                panic!("ExecEventDecoder encountered NONE event_type");
            }
            ffi::MONAD_EXEC_RECORD_ERROR => {
                ExecEventRef::RecordError(ref_from_bytes(bytes).expect("RecordError event valid"))
            }
            ffi::MONAD_EXEC_BLOCK_START => {
                let e: &monad_exec_block_start = ref_from_bytes(bytes).expect("BlockStart event valid");
                tracer_log!(
                    "event[seqno={}] block_start num={} round={} epoch={} txn_count={} timestamp={} gas_limit={} base_fee={}",
                    info.seqno,
                    e.block_tag.block_number,
                    e.round,
                    e.epoch,
                    e.eth_block_input.txn_count,
                    e.eth_block_input.timestamp,
                    e.eth_block_input.gas_limit,
                    e.eth_block_input.base_fee_per_gas.limbs[0]
                );
                ExecEventRef::BlockStart(e)
            }
            ffi::MONAD_EXEC_BLOCK_REJECT => {
                let e: &monad_exec_block_reject = ref_from_bytes(bytes).expect("BlockReject event valid");
                tracer_log!("event[seqno={}] block_reject code={}", info.seqno, *e);
                ExecEventRef::BlockReject(e)
            }
            ffi::MONAD_EXEC_BLOCK_PERF_EVM_ENTER => {
                assert_eq!(bytes.len(), 0, "BlockPerfEvmEnter payload is empty");
                tracer_log!("event[seqno={}] block_perf_evm_enter", info.seqno);
                ExecEventRef::BlockPerfEvmEnter
            }
            ffi::MONAD_EXEC_BLOCK_PERF_EVM_EXIT => {
                assert_eq!(bytes.len(), 0, "BlockPerfEvmExit payload is empty");
                tracer_log!("event[seqno={}] block_perf_evm_exit", info.seqno);
                ExecEventRef::BlockPerfEvmExit
            }
            ffi::MONAD_EXEC_BLOCK_END => {
                let e: &monad_exec_block_end = ref_from_bytes(bytes).expect("BlockEnd event valid");
                tracer_log!(
                    "event[seqno={}] block_end gas_used={} state_root={} receipts_root={} eth_block_hash={}",
                    info.seqno,
                    e.exec_output.gas_used,
                    hex::encode(e.exec_output.state_root.bytes),
                    hex::encode(e.exec_output.receipts_root.bytes),
                    hex::encode(e.eth_block_hash.bytes)
                );
                ExecEventRef::BlockEnd(e)
            }
            ffi::MONAD_EXEC_BLOCK_QC => {
                let e: &monad_exec_block_qc = ref_from_bytes(bytes).expect("BlockQC event valid");
                tracer_log!("event[seqno={}] block_qc num={} round={} epoch={}", info.seqno, e.block_tag.block_number, e.round, e.epoch);
                ExecEventRef::BlockQC(e)
            }
            ffi::MONAD_EXEC_BLOCK_FINALIZED => {
                let e: &monad_exec_block_finalized = ref_from_bytes(bytes).expect("BlockFinalized event valid");
                tracer_log!("event[seqno={}] block_finalized num={}", info.seqno, e.block_number);
                ExecEventRef::BlockFinalized(e)
            }
            ffi::MONAD_EXEC_BLOCK_VERIFIED => {
                let e: &monad_exec_block_verified = ref_from_bytes(bytes).expect("BlockVerified event valid");
                tracer_log!("event[seqno={}] block_verified num={}", info.seqno, e.block_number);
                ExecEventRef::BlockVerified(e)
            }
            ffi::MONAD_EXEC_TXN_HEADER_START => {
                let (txn_header_start, [data_bytes, blob_bytes]) =
                    ref_from_bytes_with_trailing::<monad_exec_txn_header_start, 2>(
                        bytes,
                        |txn_header_start| {
                            [
                                txn_header_start.txn_header.data_length.try_into().unwrap(),
                                TryInto::<usize>::try_into(
                                    txn_header_start.txn_header.blob_versioned_hash_length,
                                )
                                .unwrap()
                                .checked_mul(size_of::<ffi::monad_c_bytes32>())
                                .unwrap(),
                            ]
                        },
                    )
                    .expect("TxnHeaderStart event valid");

                let txn_index = info
                    .flow_info
                    .txn_idx
                    .expect("TxnHeaderStart event has txn_idx in flow_info");
                tracer_log!(
                    "event[seqno={}] txn_header_start txn={} from={} to={} value={} gas={} max_fee={} priority_fee={} chain_id={} txn_type={:?} nonce={} contract_creation={} access_list_count={} auth_list_count={}",
                    info.seqno,
                    txn_index,
                    hex::encode(txn_header_start.sender.bytes),
                    if txn_header_start.txn_header.is_contract_creation { "contract_create".to_string() } else { hex::encode(txn_header_start.txn_header.to.bytes) },
                    u256_hex(&txn_header_start.txn_header.value.limbs),
                    txn_header_start.txn_header.gas_limit,
                    txn_header_start.txn_header.max_fee_per_gas.limbs[0],
                    txn_header_start.txn_header.max_priority_fee_per_gas.limbs[0],
                    txn_header_start.txn_header.chain_id.limbs[0],
                    txn_header_start.txn_header.txn_type,
                    txn_header_start.txn_header.nonce,
                    txn_header_start.txn_header.is_contract_creation,
                    txn_header_start.txn_header.access_list_count,
                    txn_header_start.txn_header.auth_list_count
                );
                ExecEventRef::TxnHeaderStart { txn_index, txn_header_start, data_bytes, blob_bytes }
            }
            ffi::MONAD_EXEC_TXN_ACCESS_LIST_ENTRY => {
                let (txn_access_list_entry, [storage_key_bytes]) =
                    ref_from_bytes_with_trailing::<monad_exec_txn_access_list_entry, 1>(
                        bytes,
                        |txn_access_list_entry| {
                            [TryInto::<usize>::try_into(
                                txn_access_list_entry.entry.storage_key_count,
                            )
                            .unwrap()
                            .checked_mul(size_of::<ffi::monad_c_bytes32>())
                            .unwrap()]
                        },
                    )
                    .expect("TxnAccessListEntry event valid");

                let txn_index = info
                    .flow_info
                    .txn_idx
                    .expect("TxnAccessListEntry event has txn_idx in flow_info");
                tracer_log!(
                    "event[seqno={}] txn_access_list_entry txn={} idx={} keys={}",
                    info.seqno,
                    txn_index,
                    txn_access_list_entry.index,
                    txn_access_list_entry.entry.storage_key_count
                );
                ExecEventRef::TxnAccessListEntry { txn_index, txn_access_list_entry, storage_key_bytes }
            }
            ffi::MONAD_EXEC_TXN_AUTH_LIST_ENTRY => {
                let txn_index = info
                    .flow_info
                    .txn_idx
                    .expect("TxnAuthListEntry event has txn_idx in flow_info");
                let txn_auth_list_entry: &monad_exec_txn_auth_list_entry = ref_from_bytes(bytes).expect("TxnAuthListEntry event valid");
                tracer_log!(
                    "event[seqno={}] txn_auth_list_entry txn={} idx={} valid={}",
                    info.seqno,
                    txn_index,
                    txn_auth_list_entry.index,
                    txn_auth_list_entry.is_valid_authority as u8
                );
                ExecEventRef::TxnAuthListEntry { txn_index, txn_auth_list_entry }
            }
            ffi::MONAD_EXEC_TXN_HEADER_END => {
                assert_eq!(bytes.len(), 0, "TxnHeaderEnd payload is empty");
                tracer_log!("event[seqno={}] txn_header_end txn={}", info.seqno, txn_str(info.flow_info.txn_idx));
                ExecEventRef::TxnHeaderEnd
            }
            ffi::MONAD_EXEC_TXN_REJECT => {
                let txn_index = info.flow_info.txn_idx.expect("TxnReject event has txn_idx in flow_info");
                let reject: &monad_exec_txn_reject = ref_from_bytes(bytes).expect("TxnReject event valid");
                tracer_log!("event[seqno={}] txn_reject txn={} code={}", info.seqno, txn_index, *reject);
                ExecEventRef::TxnReject { txn_index, reject }
            }
            ffi::MONAD_EXEC_TXN_PERF_EVM_ENTER => {
                assert_eq!(bytes.len(), 0, "TxnPerfEvmEnter payload is empty");
                tracer_log!("event[seqno={}] txn_perf_evm_enter txn={}", info.seqno, txn_str(info.flow_info.txn_idx));
                ExecEventRef::TxnPerfEvmEnter
            }
            ffi::MONAD_EXEC_TXN_PERF_EVM_EXIT => {
                assert_eq!(bytes.len(), 0, "TxnPerfEvmExit payload is empty");
                tracer_log!("event[seqno={}] txn_perf_evm_exit txn={}", info.seqno, txn_str(info.flow_info.txn_idx));
                ExecEventRef::TxnPerfEvmExit
            }
            ffi::MONAD_EXEC_TXN_EVM_OUTPUT => {
                let txn_index = info.flow_info.txn_idx.expect("TxnEvmOutput event has txn_idx in flow_info");
                let output: &monad_exec_txn_evm_output = ref_from_bytes(bytes).expect("TxnEvmOutput event valid");
                tracer_log!(
                    "event[seqno={}] txn_evm_output txn={} gas_used={} status={} call_frame_count={}",
                    info.seqno,
                    txn_index,
                    output.receipt.gas_used,
                    output.receipt.status as u8,
                    output.call_frame_count
                );
                ExecEventRef::TxnEvmOutput { txn_index, output }
            }
            ffi::MONAD_EXEC_TXN_LOG => {
                let (txn_log, [topic_bytes, data_bytes]) =
                    ref_from_bytes_with_trailing::<monad_exec_txn_log, 2>(bytes, |txn_log| {
                        [
                            Into::<usize>::into(txn_log.topic_count)
                                .checked_mul(size_of::<ffi::monad_c_bytes32>())
                                .unwrap(),
                            txn_log.data_length.try_into().unwrap(),
                        ]
                    })
                    .expect("TxnLog event valid");

                let txn_index = info
                    .flow_info
                    .txn_idx
                    .expect("TxnLog event has txn_idx in flow_info");
                tracer_log!(
                    "event[seqno={}] txn_log txn={} idx={} addr={} topics={} data_len={} data={} topic_bytes={}",
                    info.seqno,
                    txn_index,
                    txn_log.index,
                    hex::encode(txn_log.address.bytes),
                    txn_log.topic_count,
                    txn_log.data_length,
                    hex::encode(data_bytes),
                    hex::encode(topic_bytes)
                );
                ExecEventRef::TxnLog { txn_index, txn_log, topic_bytes, data_bytes }
            }
            ffi::MONAD_EXEC_TXN_CALL_FRAME => {
                let (txn_call_frame, [input_bytes, return_bytes]) =
                    ref_from_bytes_with_trailing::<monad_exec_txn_call_frame, 2>(
                        bytes,
                        |txn_call_frame| {
                            [
                                txn_call_frame.input_length.try_into().unwrap(),
                                txn_call_frame.return_length.try_into().unwrap(),
                            ]
                        },
                    )
                    .expect("TxnCallFrame event valid");

                let call_value_hex = u256_hex(&txn_call_frame.value.limbs);
                tracer_log!(
                    "event[seqno={}] tx_call_frame txn={} idx={} depth={} opcode={:#04x} gas={} gas_used={} status={} caller={} target={} value={} input_len={} input={} return_len={} return_data={}",
                    info.seqno,
                    txn_str(info.flow_info.txn_idx),
                    txn_call_frame.index,
                    txn_call_frame.depth,
                    txn_call_frame.opcode,
                    txn_call_frame.gas,
                    txn_call_frame.gas_used,
                    txn_call_frame.evmc_status,
                    hex::encode(txn_call_frame.caller.bytes),
                    hex::encode(txn_call_frame.call_target.bytes),
                    call_value_hex,
                    txn_call_frame.input_length,
                    hex::encode(input_bytes),
                    txn_call_frame.return_length,
                    hex::encode(return_bytes)
                );
                ExecEventRef::TxnCallFrame {
                    txn_index: info.flow_info.txn_idx.expect("TxnCallFrame event has txn_idx in flow_info"),
                    txn_call_frame,
                    input_bytes,
                    return_bytes,
                }
            }
            ffi::MONAD_EXEC_TXN_END => {
                assert_eq!(bytes.len(), 0, "TxnEnd payload is empty");
                tracer_log!("event[seqno={}] txn_end txn={}", info.seqno, txn_str(info.flow_info.txn_idx));
                ExecEventRef::TxnEnd
            }
            ffi::MONAD_EXEC_ACCOUNT_ACCESS_LIST_HEADER => {
                let e: &monad_exec_account_access_list_header = ref_from_bytes(bytes).expect("AccountAccessListHeader event valid");
                tracer_log!(
                    "event[seqno={}] account_access_list_header txn={} count={} ctx={}",
                    info.seqno,
                    txn_str(info.flow_info.txn_idx),
                    e.entry_count,
                    e.access_context as u32
                );
                ExecEventRef::AccountAccessListHeader(e)
            }
            ffi::MONAD_EXEC_ACCOUNT_ACCESS => {
                let e: &monad_exec_account_access = ref_from_bytes(bytes).expect("AccountAccess event valid");
                let pre_bal_hex = u256_hex(&e.prestate.balance.limbs);
                let mod_bal_hex = u256_hex(&e.modified_balance.limbs);
                tracer_log!(
                    "event[seqno={}] account_access txn={} idx={} addr={} balance_mod={} nonce_mod={} ctx={} pre_nonce={} pre_bal={} pre_codehash={} mod_bal={} mod_nonce={} storage_count={} transient_count={}",
                    info.seqno,
                    txn_str(info.flow_info.txn_idx),
                    e.index,
                    hex::encode(e.address.bytes),
                    e.is_balance_modified as u8,
                    e.is_nonce_modified as u8,
                    e.access_context as u32,
                    e.prestate.nonce,
                    pre_bal_hex,
                    hex::encode(e.prestate.code_hash.bytes),
                    mod_bal_hex,
                    e.modified_nonce,
                    e.storage_key_count,
                    e.transient_count
                );
                ExecEventRef::AccountAccess(e)
            }
            ffi::MONAD_EXEC_STORAGE_ACCESS => {
                let e: &monad_exec_storage_access = ref_from_bytes(bytes).expect("StorageAccess event valid");
                tracer_log!(
                    "event[seqno={}] storage_access txn={} acct_idx={} addr={} modified={} transient={} slot_idx={} key={} start_val={} end_val={}",
                    info.seqno,
                    txn_str(info.flow_info.txn_idx),
                    info.flow_info.account_idx,
                    hex::encode(e.address.bytes),
                    e.modified as u8,
                    e.transient as u8,
                    e.index,
                    hex::encode(e.key.bytes),
                    hex::encode(e.start_value.bytes),
                    hex::encode(e.end_value.bytes)
                );
                ExecEventRef::StorageAccess(e)
            }
            ffi::MONAD_EXEC_EVM_ERROR => {
                let e: &monad_exec_evm_error = ref_from_bytes(bytes).expect("EvmError event valid");
                tracer_log!("event[seqno={}] evm_error domain={} status={} txn={} call_frame_idx={}", info.seqno, e.domain_id, e.status_code, txn_str(info.flow_info.txn_idx), info.flow_info.account_idx);
                ExecEventRef::EvmError(e)
            }
            ffi::MONAD_EXEC_BLOCK_SYSTEM_CALL_START => {
                let (system_call_start, [input_bytes]) =
                    ref_from_bytes_with_trailing::<monad_exec_block_system_call_start, 1>(
                        bytes,
                        |e| [e.input_length.try_into().unwrap()],
                    )
                    .expect("BlockSystemCallStart event valid");
                tracer_log!(
                    "event[seqno={}] block_system_call_start caller={} target={} opcode={:#04x} gas={} input_len={}",
                    info.seqno,
                    hex::encode(system_call_start.caller.bytes),
                    hex::encode(system_call_start.call_target.bytes),
                    system_call_start.opcode,
                    system_call_start.gas,
                    system_call_start.input_length
                );
                ExecEventRef::BlockSystemCallStart { system_call_start, input_bytes }
            }
            ffi::MONAD_EXEC_BLOCK_SYSTEM_CALL_END => {
                let (system_call_end, [return_bytes]) =
                    ref_from_bytes_with_trailing::<monad_exec_block_system_call_end, 1>(
                        bytes,
                        |e| [e.return_length.try_into().unwrap()],
                    )
                    .expect("BlockSystemCallEnd event valid");
                tracer_log!(
                    "event[seqno={}] block_system_call_end gas_used={} status={} return_len={} num_account_accesses={}",
                    info.seqno,
                    system_call_end.gas_used,
                    system_call_end.evmc_status,
                    system_call_end.return_length,
                    system_call_end.num_account_accesses
                );
                ExecEventRef::BlockSystemCallEnd { system_call_end, return_bytes }
            }
            event_type => panic!("ExecEventDecoder encountered unknown event_type {event_type}"),
        }
    }

    fn event_ref_to_event<'ring>(event_ref: Self::EventRef<'ring>) -> Self::Event {
        Self::EventRef::into_owned(event_ref)
    }
}

#[cfg(test)]
mod test {
    use monad_event_ring::{DecodedEventRing, EventNextResult, SnapshotEventRing};

    use crate::ExecEventDecoder;

    #[test]
    fn basic_test() {
        const SNAPSHOT_NAME: &str = "ETHEREUM_MAINNET_30B_15M";
        const SNAPSHOT_ZSTD_BYTES: &[u8] =
            include_bytes!("../../test/data/exec-events-emn-30b-15m/snapshot.zst");

        let snapshot = SnapshotEventRing::<ExecEventDecoder>::new_from_zstd_bytes(
            SNAPSHOT_NAME,
            SNAPSHOT_ZSTD_BYTES,
            None,
        )
        .unwrap();

        let mut event_reader = snapshot.create_reader();

        loop {
            match event_reader.next_descriptor() {
                EventNextResult::Gap => panic!("snapshot cannot gap"),
                EventNextResult::NotReady => break,
                EventNextResult::Ready(event_descriptor) => {
                    let event = event_descriptor.try_read();

                    eprintln!("event: {event:#?}");
                }
            }
        }
    }
}
