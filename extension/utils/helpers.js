// Shared utility functions for the extension
const CloudSecUtils = {
  /**
   * Standardized logging with timestamps
   */
  log: (message, data = null) => {
    const timestamp = new Date().toISOString();
    if (data) {
      console.log(`[CloudSec ${timestamp}] ${message}`, data);
    } else {
      console.log(`[CloudSec ${timestamp}] ${message}`);
    }
  },
  
  /**
   * Promisified message sending
   */
  sendMessage: async (message) => {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          reject(chrome.runtime.lastError);
        } else {
          resolve(response);
        }
      });
    });
  },
  
  /**
   * Promisified storage get
   */
  getStorage: async (keys) => {
    return new Promise((resolve) => {
      chrome.storage.local.get(keys, (result) => {
        resolve(result);
      });
    });
  },
  
  /**
   * Promisified storage set
   */
  setStorage: async (data) => {
    return new Promise((resolve) => {
      chrome.storage.local.set(data, () => {
        resolve();
      });
    });
  }
};
