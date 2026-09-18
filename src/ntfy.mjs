// Sends the approval-needed push notification. Never include field names,
// secret paths, or values here - only the capability title, level, device
// name, and the self-reported reason.
export async function sendNotification({
  ntfyUrl,
  title,
  body,
  clickUrl,
  priority = 'high',
  tags = 'closed_lock_with_key',
  actionLabel = 'Review',
  fetchImpl = fetch,
}) {
  try {
    const res = await fetchImpl(ntfyUrl, {
      method: 'POST',
      headers: {
        title,
        priority,
        tags,
        click: clickUrl,
        actions: `view, ${actionLabel}, ${clickUrl}`,
      },
      body,
    });
    return { ok: res.ok, status: res.status };
  } catch (error) {
    return { ok: false, error: String(error?.message || error) };
  }
}
