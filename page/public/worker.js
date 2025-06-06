// The worker has its own scope and no direct access to functions/objects of the
// global scope. We import the generated JS file to make `wasm_bindgen`
// available which we need to initialize our Wasm code.
// For module workers, we use ES6 imports:
import init, { length_extension_attack, ForgedResult } from './pkg/rust_sha256_len_extension_attack.js';

console.log('Initializing worker (module mode)');

async function init_wasm_in_worker() {
    // Load the Wasm file by awaiting the Promise returned by `wasm_bindgen`.
    // The `init` function is the default export from the JS glue file.
    // It will fetch and instantiate the .wasm file.
    await init();
    console.log('Wasm module initialized in worker.');

    // Set callback to handle messages passed to the worker
    self.onmessage = async event => {
        console.log("Worker received message:", event.data);
        const { type, payload } = event.data;

        if (type === 'LENGTH_EXTENSION_ATTACK') {
            const { original_message, original_mac, data_to_append, guessed_secret_len } = payload;
            try {
                // Ensure inputs are Uint8Array if they aren't already
                // For example, if they are passed as plain arrays from main thread:
                // const original_message_u8 = new Uint8Array(original_message);
                // const original_mac_u8 = new Uint8Array(original_mac);
                // const data_to_append_u8 = new Uint8Array(data_to_append);
                // Assuming they are already Uint8Array for this example:

                const result = length_extension_attack(
                    original_message,
                    original_mac,
                    data_to_append,
                    guessed_secret_len
                );

                // result is a ForgedResult object. Its getters return Uint8Array.
                self.postMessage({ type: 'RESULT', payload: { message: result.message, digest: result.digest } });
                result.free(); // Important: free Wasm memory
            } catch (e) {
                console.error("Error during length extension attack in worker:", e);
                self.postMessage({ type: 'ERROR', payload: e.message });
            }
        }
    };
    self.postMessage({ type: 'READY' }); // Signal that the worker is ready
};

init_wasm_in_worker().catch(e => console.error("Error initializing Wasm in worker:", e));
