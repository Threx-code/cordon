// Legitimate base64 decoding of user content. Decode with no execution.
export function dataUrlToBlob(dataUrl) {
  const [meta, encoded] = dataUrl.split(",");
  const mime = meta.match(/:(.*?);/)[1];
  const binary = atob(encoded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new Blob([bytes], { type: mime });
}
