// @flow

/* eslint-disable promise/avoid-new */

export default function poll(
    check: () => mixed,
    wait: number = 0,
    timeout: number = 1000
): Promise<*> {
    return new Promise((resolve, reject) => {
        let poller = setTimeout(poll, 0);
const checkStopper = setTimeout(stop, timeout);

function poll() {
    const result = check();
    if (result) {
        clearTimeout(checkStopper);
        resolve(result);
    } else {
        poller = setTimeout(poll, wait);
    }
}

function stop() {
    clearTimeout(poller);
    reject(new Error(`No result within ${timeout}ms`));
}
});
}

export function pollElement(
    window: WindowProxy,
    selector: string,
    timeout: number = 5000
) {
    return poll(() => window.document.querySelector(selector), 0, timeout);
}
