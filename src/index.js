import { connect } from 'cloudflare:sockets'
let sha224Password = '39ee80aacdf3a3ccd8b88cca463d2e82d5efb3864b2dd9aca00e8997'

const WS_READY_STATE_OPEN = 1
const WS_READY_STATE_CLOSING = 2

/**
 * @typedef {import("@cloudflare/workers-types").Request} Request
 * @typedef {import("@cloudflare/workers-types").ExecutionContext} ExecutionContext
 * @typedef {import("@cloudflare/workers-types").WebSocket} WebSocket
 * @typedef {import("@cloudflare/workers-types").Socket} Socket
 */

export default {
  /**
   * @param {Request} request
   * @param {{SHA224PASS: string}} env
   * @param {ExecutionContext} ctx
   * @returns {Promise<Response>}
   */
  async fetch(request, env, ctx) {
    try {
      sha224Password = env.SHA224PASS || sha224Password
      const upgrade = request.headers.get('Upgrade')
      if (upgrade === 'websocket') return trojanOverWSHandler()
      const url = new URL(request.url)
      switch (url.pathname) {
        case '/link':
          const host = request.headers.get('Host')
          return new Response(`trojan://fwqaaq@${host}:443/?type=ws&host=${host}&security=tls`, {
            status: 200,
            headers: {
              'Content-Type': 'text/plain;charset=utf-8',
            },
          })
        default:
          return new Response('404 Not Found', { status: 404 })
      }
    } catch (e) {
      return new Response(e.toString())
    }
  },
}

function trojanOverWSHandler() {
  /**@type {WebSocket[]} */
  const webSocketPair = new WebSocketPair()
  const [client, webSocket] = Object.values(webSocketPair)
  webSocket.accept()
  let address = ''
  let portWithRandomLog = ''
  const log = (/**@type {string}*/ info, /**@type {string} */ event) => {
    console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '')
  }

  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, log)
  /**@type {{value: WritableStream<Uint8Array> | null}} */
  const remoteSocketWrapper = { value: null }
  const writableStream = new WritableStream({
    async write(/**@type {ArrayBuffer}*/ chunk) {
      if (remoteSocketWrapper.value) {
        const writer = remoteSocketWrapper.value.getWriter()
        writer.write(chunk)
        writer.releaseLock()
        return
      }

      // handle the first chunk
      const { remotePort = 443, remoteAddress = '', payload } = parseTrojanHeader(chunk)

      address = remoteAddress
      portWithRandomLog = `${remotePort}--${Math.random()} tcp`

      handleTCPOutBound(remoteSocketWrapper, remoteAddress, remotePort, payload, webSocket, log)
    },
    close() {
      log(`readableWebSocketStream is closed`)
    },
    abort(reason) {
      log(`readableWebSocketStream is aborted`, JSON.stringify(reason))
    },
  })
  readableWebSocketStream.pipeTo(writableStream).catch((e) => {
    log('readableWebSocketStream pipeTo error', e)
  })
  return new Response(null, {
    status: 101,
    webSocket: client,
  })
}

const decoder = new TextDecoder()
/**
 * @param {ArrayBuffer} chunk
 * @param {(string, string) => void} log
 * @link https://trojan-gfw.github.io/trojan/protocol
 */
function parseTrojanHeader(chunk) {
  if (chunk.byteLength < 56) throw new Error('Invalid data')

  // CRLF = 0x0D 0x0A
  const crlf = new Uint8Array(chunk.slice(56, 58))
  if (crlf[0] !== 0x0d || crlf[1] !== 0x0a) throw new Error('Invalid CRLF for Trojan First Chunk')

  const password = decoder.decode(chunk.slice(0, 56))
  if (password !== sha224Password) throw new Error('Invalid password')

  const view = new DataView(chunk.slice(58))
  const cmd = view.getUint8(0)
  if (cmd !== 1) throw new Error('Unsupported command, only TCP (CONNECT) is allowed')

  const type = view.getUint8(1)
  // Trojan Request Header Format after first CRLF
  // +-----+------+----------+----------+
  // | CMD | ATYP | DST.ADDR | DST.PORT |
  // +-----+------+----------+----------+
  // |  1  |  1   | Variable |    2     |
  // +-----+------+----------+----------+
  let addressLength = 0

  let address = ''
  switch (type) {
    case 0x01:
      addressLength = 4
      address = new Uint8Array(view.buffer.slice(2, 2 + addressLength)).join('.')
      break
    case 0x03:
      addressLength = view.getUint8(2)
      address = decoder.decode(view.buffer.slice(3, 3 + addressLength))
      break
    case 0x04:
      addressLength = 16
      address = Array(8)
        .fill(0)
        .map((_, i) => view.getUint16(2 + i * 2).toString(16))
        .join(':')
      break
    default:
      throw new Error(`invalid addressType is ${type}`)
  }

  if (!address) throw new Error(`address is empty, addressType is ${type}`)

  const portIndex = (type === 0x03 ? 3 : 2) + addressLength
  const port = view.getUint16(portIndex)
  return {
    remoteAddress: address,
    remotePort: port,
    payload: view.buffer.slice(portIndex + 4),
  }
}

/**
 * @param {WebSocket} webSocket
 * @param {(string, string) => void} log
 * @returns {ReadableStream<ArrayBuffer>}
 */
function makeReadableWebSocketStream(webSocket, log) {
  let cancel = false
  const stream = new ReadableStream({
    start(/**@type {ReadableStreamController<ArrayBuffer>}*/ controller) {
      webSocket.addEventListener('message', (event) => {
        if (cancel) return
        controller.enqueue(event.data)
      })
      webSocket.addEventListener('close', () => {
        safeCloseWebSocket(webSocket)
        if (cancel) return
        controller.close()
      })
      webSocket.addEventListener('error', (event) => {
        log('WebSocket closed error')
        controller.error(event)
      })
    },
    cancel(reason) {
      log('WebSocket closed error')
      log(`readableStream was canceled, due to ${reason}`)
      cancel = true
      safeCloseWebSocket(webSocket)
    },
  })
  return stream
}

/**
 * @param {{value: WritableStream<Uint8Array> | null}} remoteSocket
 * @param {string} remoteAddress
 * @param {number} remotePort
 * @param {Uint8Array} payload
 * @param {WebSocket} client
 * @param {(string, string) => void} log
 */
async function handleTCPOutBound(remoteSocket, remoteAddress, remotePort, payload, client, log) {
  // client payload -> tcp Socket
  const connectAndWrite = async (/**@type {string} */ hostname, /**@type {number} */ port) => {
    /**@type {import("@cloudflare/workers-types").Socket} */
    const tcpSocket = connect({ hostname, port })
    remoteSocket.value = tcpSocket.writable

    log(`Connected to ${hostname}:${port}`)

    const writer = tcpSocket.writable.getWriter()
    await writer.write(payload)
    writer.releaseLock()
    return tcpSocket
  }

  const retry = async () => {
    const tcpSocket = await connectAndWrite(remoteAddress, remotePort)

    tcpSocket.closed
      .catch((e) => {
        log(`Retry to connect ${hostname}:${port} failed`, e)
      })
      .finally(() => {
        safeCloseWebSocket(client)
      })

    tcpSocketToWS(tcpSocket, client, null, log)
  }

  const tcpSocket = await connectAndWrite(remoteAddress, remotePort)

  // tcp Socket -> client (WebSocket)
  tcpSocketToWS(tcpSocket, client, retry, log)
}

/**
 * @param {Socket} tcpSocket
 * @param {WebSocket} webSocket
 * @param {function} retry
 * @param {(string, string) => void} log
 */
async function tcpSocketToWS(tcpSocket, webSocket, retry, log) {
  let hasIncomingData = false
  const writableStream = new WritableStream({
    async write(/**@type {ArrayBuffer}*/ chunk, controller) {
      hasIncomingData = true
      if (webSocket.readyState !== WS_READY_STATE_OPEN) {
        controller.error('webSocket connection is not open')
      }
      webSocket.send(chunk)
    },
    close() {
      log(`tcpSocket.readable is closed, hasIncomingData: ${hasIncomingData}`)
    },
    abort(reason) {
      console.error('tcpSocket.readable abort', reason)
    },
  })
  await tcpSocket.readable.pipeTo(writableStream).catch((e) => {
    log('tcpSocket pipeTo WebSocket error:', e.stack || e)
    safeCloseWebSocket(webSocket)
  })
  if (!hasIncomingData && retry) {
    log('No incoming data, retrying...')
    retry()
  }
}

/**
 * @param {WebSocket} webSocket
 * @link https://developer.mozilla.org/en-US/docs/Web/API/WebSocket/readyState
 **/
function safeCloseWebSocket(webSocket) {
  try {
    if (webSocket.readyState === WS_READY_STATE_OPEN || webSocket.readyState === WS_READY_STATE_CLOSING) webSocket.close()
  } catch (error) {
    console.error('safeCloseWebSocket error', error)
  }
}
