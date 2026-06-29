export function hasKevDataBinding(env) {
  return Boolean(env.KEV_DATA);
}

export function getR2Object(env, key) {
  return env.KEV_DATA.get(key);
}

export function putR2Object(env, key, body, contentType) {
  return env.KEV_DATA.put(key, body, {
    httpMetadata: {
      contentType,
    },
  });
}
