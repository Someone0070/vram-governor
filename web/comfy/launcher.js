(() => {
  'use strict'

  const mountPath = new URL('.', window.location.href).pathname
  const csrfStorageKey = 'comfy-canvas.csrf'
  const csrfSafeMethods = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE'])
  const sessionPath = '/auth/session'
  const loginForm = document.getElementById('canvas-login-form')
  let loginCard = document.getElementById('canvas-login')
  const credentialInput = document.getElementById('canvas-credential')
  const submitButton = document.getElementById('canvas-login-submit')
  const statusLine = document.getElementById('canvas-login-status')
  let csrf = readSessionCsrf()
  let appStarted = false
  let sessionExchangeInProgress = false

  function readSessionCsrf() {
    try {
      return window.sessionStorage.getItem(csrfStorageKey) || ''
    } catch {
      return ''
    }
  }

  function saveSessionCsrf(value) {
    csrf = value
    try {
      if (value) window.sessionStorage.setItem(csrfStorageKey, value)
      else window.sessionStorage.removeItem(csrfStorageKey)
    } catch {
      // The in-memory token remains scoped to this tab when storage is unavailable.
    }
  }

  function clearSessionCsrf() {
    saveSessionCsrf('')
  }

  function isApiPath(url) {
    return url.pathname.startsWith(`${mountPath}api/`) ||
      url.pathname === `${mountPath}api`
  }

  function isStaticCanvasPath(url) {
    return url.pathname === mountPath ||
      url.pathname.startsWith(`${mountPath}dist/`) ||
      url.pathname.startsWith(`${mountPath}templates/`) ||
      url.pathname.startsWith(`${mountPath}upstream/`) ||
      url.pathname.startsWith(`${mountPath}notices/`) ||
      url.pathname === `${mountPath}launcher.js`
  }

  function authorizeDestination(input, method, allowSessionExchange = false) {
    const url = new URL(input, window.location.href)
    const normalizedMethod = String(method || 'GET').toUpperCase()

    if (url.protocol === 'data:' || url.protocol === 'blob:') return { url, headers: null }
    if (url.origin !== window.location.origin) {
      throw new TypeError('Comfy canvas only sends requests to this Load Balancer Plus origin.')
    }

    const isSessionExchange =
      allowSessionExchange &&
      sessionExchangeInProgress &&
      url.pathname === sessionPath &&
      normalizedMethod === 'POST'

    if (!isSessionExchange && !isApiPath(url) && !isStaticCanvasPath(url)) {
      throw new TypeError(`Comfy canvas blocked an unclassified same-origin route: ${url.pathname}`)
    }

    if (isApiPath(url) && !csrfSafeMethods.has(normalizedMethod) && !csrf) {
      throw new Error('The UI session has expired. Sign in again before changing canvas data.')
    }

    return { url, normalizedMethod, isApi: isApiPath(url), isSessionExchange }
  }

  function noteUnauthorized(status, url) {
    if ((status === 401 || status === 403) && isApiPath(url)) {
      clearSessionCsrf()
      showSessionOverlay('The UI session expired or lacks the required scope. Sign in again to continue.')
      window.dispatchEvent(new CustomEvent('comfy-canvas-session-expired'))
    }
  }

  function addCsrfHeader(headers) {
    const next = new Headers(headers || undefined)
    if (csrf) next.set('X-CSRF-Token', csrf)
    return next
  }

  const nativeFetch = window.fetch.bind(window)
  window.fetch = async function canvasScopedFetch(input, init = {}) {
    const initialUrl = input instanceof Request ? input.url : input
    const initialMethod = init.method || (input instanceof Request ? input.method : 'GET')
    const checked = authorizeDestination(initialUrl, initialMethod, true)
    const headers = new Headers(input instanceof Request ? input.headers : undefined)
    new Headers(init.headers || undefined).forEach((value, name) => headers.set(name, value))
    if (checked.isApi && !csrfSafeMethods.has(checked.normalizedMethod)) {
      if (!csrf) throw new Error('The UI session has expired. Sign in again before changing canvas data.')
      headers.set('X-CSRF-Token', csrf)
    }
    const response = await nativeFetch(input, {
      ...init,
      method: checked.normalizedMethod,
      headers,
      credentials: 'same-origin',
      redirect: 'error'
    })
    noteUnauthorized(response.status, checked.url)
    return response
  }

  const xhrState = new WeakMap()
  const nativeOpen = XMLHttpRequest.prototype.open
  const nativeSend = XMLHttpRequest.prototype.send
  XMLHttpRequest.prototype.open = function canvasScopedOpen(method, url, ...rest) {
    const checked = authorizeDestination(url, method)
    xhrState.set(this, checked)
    return nativeOpen.call(this, method, url, ...rest)
  }
  XMLHttpRequest.prototype.send = function canvasScopedSend(body) {
    const checked = xhrState.get(this)
    if (!checked) throw new Error('Comfy canvas blocked an XHR without a classified request URL.')
    if (checked.isApi && !csrfSafeMethods.has(checked.normalizedMethod)) {
      if (!csrf) throw new Error('The UI session has expired. Sign in again before changing canvas data.')
      this.setRequestHeader('X-CSRF-Token', csrf)
    }
    this.addEventListener('loadend', () => noteUnauthorized(this.status, checked.url), { once: true })
    return nativeSend.call(this, body)
  }

  const NativeWebSocket = window.WebSocket
  window.WebSocket = new Proxy(NativeWebSocket, {
    construct(target, args) {
      const url = new URL(args[0], window.location.href)
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      if (
        url.host !== window.location.host ||
        url.protocol !== protocol ||
        url.pathname !== `${mountPath}ws` ||
        url.searchParams.has('token')
      ) {
        throw new TypeError('Comfy canvas only opens its same-origin /comfy/ws connection.')
      }
      return Reflect.construct(target, args)
    }
  })

  if (navigator.sendBeacon) {
    navigator.sendBeacon = () => false
  }

  function showSessionOverlay(message) {
    let overlay = document.getElementById('canvas-session-overlay')
    if (!overlay) {
      overlay = document.createElement('div')
      overlay.id = 'canvas-session-overlay'
      overlay.setAttribute('role', 'dialog')
      overlay.setAttribute('aria-modal', 'true')
      overlay.setAttribute('aria-labelledby', 'canvas-title')
      overlay.append(loginCard)
      document.body.append(overlay)
    }
    loginCard.hidden = false
    overlay.hidden = false
    statusLine.textContent = message
    credentialInput.focus()
  }

  function addServiceNotice() {
    const notice = document.createElement('aside')
    notice.id = 'canvas-service-notice'
    notice.setAttribute('role', 'note')
    const message = document.createElement('span')
    message.textContent = 'This canvas provides the built-in editor and the two registered model workflows. Custom-node and extension managers, remote template catalogs, internal server controls, subgraphs, cloud collaboration, and worker-based 3D tools are unavailable.'
    const license = document.createElement('a')
    license.href = `${mountPath}upstream/frontend-1.51.9/LICENSE`
    license.textContent = ' GPL-3.0 license'
    const close = document.createElement('button')
    close.type = 'button'
    close.textContent = 'Dismiss'
    close.addEventListener('click', () => notice.remove())
    notice.append(message, license, close)
    document.body.append(notice)
  }

  async function startEditor() {
    if (appStarted) return
    const response = await window.fetch(`${mountPath}dist/index.html`, { cache: 'no-store' })
    if (!response.ok) throw new Error(`Could not load the pinned ComfyUI editor (${response.status}).`)
    const html = await response.text()
    const source = new DOMParser().parseFromString(html, 'text/html')
    const base = document.createElement('base')
    base.href = `${mountPath}dist/`
    document.head.prepend(base)
    if (source.title) document.title = source.title
    source.querySelectorAll('meta[name], meta[property]').forEach((meta) => {
      if (meta.hasAttribute('charset') || meta.name === 'viewport') return
      document.head.append(meta.cloneNode(true))
    })
    source.querySelectorAll('link[rel="modulepreload"], link[rel="stylesheet"], link[rel="manifest"], link[rel="icon"]').forEach((link) => {
      const href = link.getAttribute('href') || ''
      if (href.includes('userdata/user.css') || href === 'user.css') return
      document.head.append(link.cloneNode(true))
    })

    const form = loginCard
    document.body.className = source.body.className
    document.body.replaceChildren(...Array.from(source.body.childNodes).map((node) => node.cloneNode(true)))
    loginCard = form
    addServiceNotice()
    const sessionOverlay = document.createElement('div')
    sessionOverlay.id = 'canvas-session-overlay'
    sessionOverlay.setAttribute('role', 'dialog')
    sessionOverlay.setAttribute('aria-modal', 'true')
    sessionOverlay.setAttribute('aria-labelledby', 'canvas-title')
    sessionOverlay.hidden = true
    sessionOverlay.append(form)
    document.body.append(sessionOverlay)

    source.querySelectorAll('script[type="module"][src]').forEach((original) => {
      const script = document.createElement('script')
      script.type = 'module'
      script.crossOrigin = 'anonymous'
      script.src = original.getAttribute('src')
      document.head.append(script)
    })
    appStarted = true
  }

  async function exchangeCredential(event) {
    event.preventDefault()
    const submittedCredential = credentialInput.value
    if (!submittedCredential) return
    submitButton.disabled = true
    statusLine.textContent = 'Opening a scoped UI session…'
    sessionExchangeInProgress = true
    try {
      const response = await window.fetch(sessionPath, {
        method: 'POST',
        cache: 'no-store',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: submittedCredential, kind: 'ui' })
      })
      const body = await response.json().catch(() => ({}))
      if (!response.ok || typeof body.csrf_token !== 'string' || body.csrf_token.length < 16) {
        throw new Error('The server did not accept this UI credential.')
      }
      saveSessionCsrf(body.csrf_token)
      statusLine.textContent = ''
      const overlay = document.getElementById('canvas-session-overlay')
      if (overlay) overlay.hidden = true
      await startEditor()
    } catch (error) {
      statusLine.textContent = error instanceof Error ? error.message : 'Could not open a UI session.'
    } finally {
      sessionExchangeInProgress = false
      credentialInput.value = ''
      submitButton.disabled = false
    }
  }

  loginForm.addEventListener('submit', exchangeCredential)

  if (csrf) {
    loginCard.hidden = true
    startEditor().catch((error) => {
      loginCard.hidden = false
      statusLine.textContent = error instanceof Error ? error.message : 'Could not load the editor.'
    })
  }
})()
