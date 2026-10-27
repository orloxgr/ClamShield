// Electron's workArea and BrowserWindow bounds both use device-independent pixels.
function notificationLayout(workArea, sizes) {
  const margin = Math.min(20, Math.floor(Math.min(workArea.width, workArea.height) / 10));
  const gap = 12;
  const width = Math.min(460, workArea.width - margin * 2);
  let right = workArea.x + workArea.width - margin;
  let bottom = workArea.y + workArea.height - margin;
  return sizes.map(size => {
    const height = Math.min(size.height, workArea.height - margin * 2);
    if (bottom - height < workArea.y + margin) {
      right -= width + gap;
      bottom = workArea.y + workArea.height - margin;
    }
    if (right - width < workArea.x + margin) return null; // Wait for a free slot.
    const bounds = { x: right - Math.min(width, size.width), y: bottom - height, width: Math.min(width, size.width), height };
    bottom -= height + gap;
    return bounds;
  });
}

module.exports = { notificationLayout };
