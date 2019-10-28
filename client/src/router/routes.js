
const routes = [
  {
    path: '/',
    component: () => import('layouts/Main'),
    children: [
      { path: '', component: () => import('pages/Index.vue') },
    ],
  },
  {
    path: '/login',
    component: () => import('layouts/Main'),
    children: [
      { path: '', component: () => import('pages/Login'), props: { tab: 'login' } },
    ],
  },
  {
    path: '/register',
    component: () => import('layouts/Main'),
    children: [
      { path: '', component: () => import('pages/Login'), props: { tab: 'register' } },
    ],
  },
];

// Always leave this as last one
if (process.env.MODE !== 'ssr') {
  routes.push({
    path: '*',
    component: () => import('pages/Error404.vue'),
  });
}

export default routes;
