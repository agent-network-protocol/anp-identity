use serde::{Deserialize, Serialize};

use crate::facade::{DocumentChangeSession, IdentityResult};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostDocumentChangePhase {
    Prepared,
    PublicationInFlight,
    PublicationUncertain,
    Published,
}

pub trait DocumentChangeRecoveryPort {
    fn host_phase(&self) -> IdentityResult<HostDocumentChangePhase>;
}

impl DocumentChangeRecoveryPort for DocumentChangeSession {
    fn host_phase(&self) -> IdentityResult<HostDocumentChangePhase> {
        Ok(match self.publication_state()? {
            crate::PublicationState::Prepared => HostDocumentChangePhase::Prepared,
            crate::PublicationState::PublicationInFlight => {
                HostDocumentChangePhase::PublicationInFlight
            }
            crate::PublicationState::PublicationUncertain => {
                HostDocumentChangePhase::PublicationUncertain
            }
            crate::PublicationState::Published => HostDocumentChangePhase::Published,
        })
    }
}
