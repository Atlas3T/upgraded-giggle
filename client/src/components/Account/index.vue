<template>
  <div>
    <q-card
      flat
      class="account q-pa-sm"
    >
      <div class="row text-weight-bold text-h6 q-mb-xs">
        {{ $t('account') }}
      </div>
      <div class="row q-gutter-x-sm q-mb-xs">
        <div><q-icon name="fas fa-user" /></div>
        <div>{{ user.name }}</div>
      </div>
      <div class="row q-gutter-x-sm q-mb-xs">
        <div><q-icon name="fas fa-envelope" /></div>
        <div>{{ user.email }}</div>
      </div>
      <div
        v-if="user.pubKey"
        class="row q-gutter-x-sm q-mb-xs"
      >
        <div><q-icon name="fas fa-key" /></div>
        <div
          class="overflow"
          style="width:90%;"
          @click="copy(user.pubKey)"
        >
          {{ user.pubKey.toLowerCase() }}
          <q-tooltip>
            {{ copyLabel }}
          </q-tooltip>
        </div>
      </div>
    </q-card>
  </div>
</template>
<script>
import User from '../../store/User';

export default {
  name: 'Account',

  data() {
    return {
      copyLabel: this.$t('copyPubKey'),
      isPwd: true,
      tiers: {
        free: 50,
        basic: 1000,
        standard: 10000,
        premium: 100000,
      },
    };
  },

  computed: {
    account() {
      const account = this.$auth.account();
      if (!account || account.idToken.tfp !== 'B2C_1_TimestampSignUpSignIn') {
        return null;
      }
      return account;
    },

    user() {
      if (this.account) {
        const user = User.query().whereId(this.account.accountIdentifier).with('timestamps').get();
        if (user) {
          return user[0];
        }
      }
      return null;
    },

    key() {
      return this.user.secretKey;
    },
  },

  methods: {
    copy(text) {
      navigator.clipboard.writeText(text.toLowerCase()).then(() => {
        this.copyLabel = this.$t('copied');
        setTimeout(() => {
          this.copyLabel = this.$t('copyPubKey');
        }, 1500);
      }, (err) => {
        console.error('Async: Could not copy text: ', err);
      });
    },
  },
};
</script>
<style lang="scss">
.account {
    border: 2px solid rgba(0, 0, 0, 0.12);
}

.signing-key {
  width: 100%;
}
</style>
