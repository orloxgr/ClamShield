import { getLocale, localizeText } from './i18n';

function padDatePart(value: number) {
  return String(value).padStart(2, "0");
}

function fallbackDateTime(date: Date) {
  return [
    date.getFullYear(),
    padDatePart(date.getMonth() + 1),
    padDatePart(date.getDate())
  ].join("/") + " " + [
    padDatePart(date.getHours()),
    padDatePart(date.getMinutes()),
    padDatePart(date.getSeconds())
  ].join(":");
}

export function formatSystemDateTime(value: string | number | Date | null | undefined, emptyText = "Never") {
  if (!value) return localizeText(emptyText);
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return localizeText(emptyText);
  try {
    return new Intl.DateTimeFormat(getLocale(), {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit"
    }).format(date);
  } catch {
    return fallbackDateTime(date);
  }
}

export function formatRelativeTime(value: string | number | Date) {
  const seconds = (new Date(value).getTime() - Date.now()) / 1000;
  if (!Number.isFinite(seconds)) return localizeText('Never');
  const units: Array<[Intl.RelativeTimeFormatUnit, number]> = [
    ['year', 31536000], ['month', 2592000], ['day', 86400], ['hour', 3600], ['minute', 60], ['second', 1]
  ];
  const [unit, divisor] = units.find(([, size]) => Math.abs(seconds) >= size) || units.at(-1)!;
  return new Intl.RelativeTimeFormat(getLocale() || 'en', { numeric: 'auto' }).format(Math.round(seconds / divisor), unit);
}
