// Shared visual token application: authoritative clinic projection or local settings preview.
// No branding identity, credentials or palette cache is used as an authorization source.
export type RuntimeTheme = {
  selected_theme?: string | null;
  primary_color?: string | null;
  secondary_color?: string | null;
  accent_color?: string | null;
  app_accent_color?: string | null;
};

const themes = new Set(['elite','emerald','rose','prestige','ocean','graphite','dark','high-contrast']);
const color = (value?: string | null) => typeof value === 'string' && /^#[0-9a-f]{6}$/i.test(value) ? value : null;

export const applyRuntimeTheme = (profile: RuntimeTheme | null, persist = false) => {
  const finalTheme = profile?.selected_theme && themes.has(profile.selected_theme) ? profile.selected_theme : 'elite';
  const root = document.documentElement;
  const body = document.body;
  const primary = color(profile?.primary_color);
  const foreground = primary ? (() => {
    // WCAG relative luminance, not a gamma-encoded brightness threshold.
    const luminance = (hex: string) => [1, 3, 5]
      .map(i => parseInt(hex.slice(i, i + 2), 16) / 255)
      .map(v => v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4)
      .reduce((sum, v, i) => sum + v * [0.2126, 0.7152, 0.0722][i], 0);
    const bg = luminance(primary);
    const white = 1.05 / (bg + 0.05);
    const black = (bg + 0.05) / 0.05;
    // Preserve the existing dark ink where it actually meets AA; use true
    // black at the transition when navy and white would both fail 4.5:1.
    if (white >= black) return '#ffffff';
    const navy = luminance('#0f172a');
    const navyRatio = (Math.max(bg, navy) + 0.05) / (Math.min(bg, navy) + 0.05);
    return navyRatio >= 4.5 ? '#0f172a' : '#000000';
  })() : null;
  const tokens = {
    '--primary': primary,
    '--secondary': color(profile?.secondary_color),
    '--accent': color(profile?.accent_color),
    '--app-accent': color(profile?.app_accent_color),
    '--text-on-primary': foreground,
  };
  for (const element of [root, body]) {
    element.dataset.theme = finalTheme === 'elite' ? '' : finalTheme;
    for (const [key,value] of Object.entries(tokens)) {
      if (value) element.style.setProperty(key,value);
      else element.style.removeProperty(key);
    }
  }
  // Legacy preference remains available to existing settings; never restore it
  // into an unverified workstation or unauthenticated surface.
  if (persist) {
    try { localStorage.setItem('digitalcrown_theme', finalTheme); } catch {}
  }
  let meta = document.querySelector('meta[name="theme-color"]');
  if (!meta) {
    meta = document.createElement('meta');
    meta.setAttribute('name','theme-color');
    document.head.appendChild(meta);
  }
  meta.setAttribute('content', ['dark','prestige'].includes(finalTheme) ? '#020617' : '#f8fafc');
};
