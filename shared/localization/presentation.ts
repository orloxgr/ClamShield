import { englishPack, translate, type LanguagePack } from './runtime';
let selected = englishPack;
export function setPresentationLanguage(pack: LanguagePack) { selected = pack; }
export function presentationText(key: string) { return translate(selected, key); }
