//! Image pull orchestration: resolve a reference, fetch the layers
//! missing from the cache, and record the manifest. Tags resolve on
//! every pull (tags are mutable; digests pin); layer bytes download
//! only on cache miss.

use super::cache::{ImageStore, LayerCache, StoredLayer, StoredManifest};
use super::download::download_blob;
use super::registry::{OciReference, RegistryClient, ResolvedImage};

/// Pull one image into the cache: resolve the current manifest,
/// download missing layers (cached layers skip the network), and
/// record the resolution. Returns the resolved image.
pub async fn ensure_image(
    client: &RegistryClient,
    cache: &LayerCache,
    store: &ImageStore,
    reference: &OciReference,
) -> Result<ResolvedImage, String> {
    let resolved = client.resolve(reference).await?;
    for layer in &resolved.layers {
        download_blob(client, reference, &layer.digest, layer.size, cache).await?;
    }
    let pulled_at_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    store.write_manifest(
        &reference.normalized(),
        &StoredManifest {
            reference: reference.normalized(),
            manifest_digest: resolved.manifest_digest.clone(),
            layers: resolved
                .layers
                .iter()
                .map(|layer| StoredLayer {
                    digest: layer.digest.clone(),
                    size: layer.size,
                })
                .collect(),
            pulled_at_secs,
        },
    )?;
    Ok(resolved)
}
