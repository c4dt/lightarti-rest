//! Functions to download or load directory objects, using the
//! state machines in the `states` module.

// Code mostly copied from Arti.

use crate::{
    DirState, Result,
};


/// Try tp update `state` by loading cached information from `dirmgr`.
/// Return true if anything changed.
async fn load_once(
    state: &mut Box<dyn DirState>,
    docdir: &str
) -> Result<bool> {
    let missing = state.missing_docs();
    if missing.is_empty() {
        Ok(false)
    } else {
        state.add_from_cache(&docdir)
    }
}

/// Try to load as much state as possible for a provided `state` from the
/// cache in `dirmgr`, advancing the state to the extent possible.
///
/// No downloads are performed; the provided state will not be reset.
pub(crate) async fn load(
    mut state: Box<dyn DirState>,
    docdir: &str
) -> Result<Box<dyn DirState>> {
    let mut safety_counter = 0_usize;
    loop {
        let changed = load_once(&mut state, &docdir).await?;

        if state.can_advance() {
            state = state.advance()?;
            safety_counter = 0;
        } else {
            if !changed {
                break;
            }
            safety_counter += 1;
            if safety_counter == 100 {
                panic!("Spent 100 iterations in the same state: this is a bug");
            }
        }
    }

    Ok(state)
}
