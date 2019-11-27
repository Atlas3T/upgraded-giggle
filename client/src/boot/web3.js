import Web3 from 'web3';
import Vue from 'vue';

const web3 = new Web3(new Web3.providers.HttpProvider('https://kovan.infura.io/v3/679bbc6759454bf58a924bfaf55576b9'));

Vue.prototype.$web3 = {
  async getTimestamp(block) {
    try {
      console.log(block);
      const blockInfo = await web3.eth.getBlock(block);
      console.log(blockInfo);
      return blockInfo.timestamp * 1000;
    } catch (e) {
      console.log(e);
    }
    return null;
  },

  async verifyTimestamp(id, hash) {
    console.log(id);
    try {
      const tx = await web3.eth.getTransaction('0x71ffbd040921b0cc01beaf26f4de7b6343ecaf2365e6d68fc55f4fdb9981e892');
      console.log(tx);
      console.log(tx.input);
      console.log(Web3.utils.hexToUtf8(tx.input));
      const info = JSON.parse(Web3.utils.hexToUtf8(tx.input));
      console.log(info.hash);
      console.log(hash);
      if (info.hash === hash) {
        const date = await this.getTimestamp(tx.blockNumber);
        return {
          verified: true,
          signature: info.signature,
          publicKey: info.publicKey,
          timestamp: date,
        };
      }

      return {
        verified: false,
      };
    } catch (error) {
      console.error(error);
      return null;
    }
  },
};
