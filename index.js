class EncryptedDataElement extends HTMLElement {
  constructor() {
    super();
    this._observer = null;
    this._inert = false;
  }

  _observerCallback(mutations) {
    for (const { addedNodes } of mutations) {
      for (const added of addedNodes) {
        if (added.localName === 'script' && added.type === 'ciphertext') {
          this._stopObserving();
          this.run();
          return;
        }
      }
    }
  }

  _startObserving() {
    if (this._inert) return;
    if (!this._observer) {
      this._observer = new MutationObserver((...args) => this._observerCallback(...args));
      this._observer.observe(this, { childList: true });
    }
  }

  _stopObserving() {
    if (this._observer) {
      this._observer.disconnect();
      this._observer = null;
    }
  }

  connectedCallback() {
    if (this._inert) return;
    if (this.querySelector('script[type=ciphertext]')) {
      this.run();
      return;
    }
    this._startObserving();
  }

  disconnectedCallback() {
    this._stopObserving();
  }

  get inert() {
    return this._inert;
  }

  get hint() {
    return this.getAttribute('hint');
  }

  get digest() {
    return this.getAttribute('digest');
  }

  get encryption() {
    return this.getAttribute('encryption');
  }

  get iv() {
    return this.getAttribute('iv');
  }

  get cipherText() {
    const el = this.querySelector('script[type=ciphertext]');
    if (!el) return el;
    return el.textContent;
  }

  async run() {
    if (this._inert) return;
    this._inert = true;

    try {
      const { hint, digest, encryption, iv, cipherText } = this;
      const prompted = prompt(hint);
      const pw = prompted.toLowerCase().trim();
      const pwUtf8 = new TextEncoder().encode(pw);
      const pwHash = await crypto.subtle.digest(digest, pwUtf8);

      const ivBuf = new TextEncoder().encode(iv);
      const alg = { name: encryption, iv: ivBuf };
      const key = await crypto.subtle.importKey('raw', pwHash, alg, false, ['decrypt']);

      const encryptedBuffer = decodeBase64(cipherText);
      const ptBuffer = await crypto.subtle.decrypt(alg, key, encryptedBuffer);
      const plainText = new TextDecoder().decode(ptBuffer);

      this.innerHTML = plainText;
    } catch (err) {
      console.error(err);
      this.textContent = 'Sad :( Refresh the page and try again';
    }
  }
}
customElements.define('encrypted-data', EncryptedDataElement);

function decodeBase64(src) {
  const strBuf = atob(src);
  const buf = new Uint8Array(strBuf.length);
  for (let i = 0; i < strBuf.length; i++) {
    buf[i] = strBuf.charCodeAt(i);
  }
  return buf.buffer;
}
