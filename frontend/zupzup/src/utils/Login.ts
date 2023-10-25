import { SOCIAL_KEY } from './Constants';

export const getSocialLoginAuthUrl = (
  domain: string,
  clientId: string,
  redirectUrl: string,
) => {
  if (domain === SOCIAL_KEY.KAKAO) {
    return `https://kauth.kakao.com/oauth/authorize?client_id=${clientId}&redirect_uri=${redirectUrl}&response_type=code`;
  }
  return '';
};
