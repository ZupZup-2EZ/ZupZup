import styled from 'styled-components';

import { SocialLoginButton } from 'components';
import { SOCIAL_KEY, getSocialLoginAuthUrl } from 'utils';

import KakaoIcon from 'assets/icons/Kakao_logo.svg?react';
import NaverIcon from 'assets/icons/Naver_logo.svg?react';
import GoogleIcon from 'assets/icons/Google_logo.svg?react';

const Login = () => {
  const handleSocialLogin = async (domain: string) => {
    //1. back 에게 요청 보내고
    // const response = await axios.get('');
    const clientId = 'abc';
    const redirectUrl = 'https://zupzup.store/login';
    window.location.href = getSocialLoginAuthUrl(domain, clientId, redirectUrl);
  };

  return (
    <S.Wrap>
      <S.LogoContainer>
        <S.Title>줍줍</S.Title>
        <S.Image src="assets/images/park_main.png"></S.Image>
      </S.LogoContainer>
      <S.LoginButton>
        <SocialLoginButton
          backgroundColor="#FAE100"
          color="#371D1E"
          onClick={() => handleSocialLogin(SOCIAL_KEY.KAKAO)}
        >
          <KakaoIcon />
          카카오톡으로 시작하기
        </SocialLoginButton>
        <SocialLoginButton
          backgroundColor="#06BE34"
          color="#FFFFFF"
          onClick={() => handleSocialLogin(SOCIAL_KEY.NAVER)}
        >
          <NaverIcon />
          네이버로 시작하기
        </SocialLoginButton>
        <SocialLoginButton
          backgroundColor="#FFFFFF"
          color="#4E5968"
          onClick={() => handleSocialLogin(SOCIAL_KEY.GOOGLE)}
        >
          <GoogleIcon />
          구글로 시작하기
        </SocialLoginButton>
      </S.LoginButton>
    </S.Wrap>
  );
};

const S = {
  Wrap: styled.div`
    display: flex;
    flex-direction: column;
    overflow: hidden;
    width: 100%;
    height: 100vh;
    background: linear-gradient(
      180deg,
      #fff 0%,
      #fff 0.01%,
      #fff 14.69%,
      #b8f2e8 48.54%,
      #2cd5fb 99.41%
    );
  `,

  LogoContainer: styled.div`
    display: flex;
    position: relative;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    height: 50vh;
  `,

  Title: styled.div`
    margin-top: 200px;
    transform: translateY(150px);
    text-align: center;
    font-family: ${({ theme }) => theme.font.family.title};
    font-size: ${({ theme }) => theme.font.size.title};
    color: ${({ theme }) => theme.color.white};
    text-shadow: 0px 4px 4px rgba(0, 0, 0, 0.3);
    z-index: 1;
  `,

  Image: styled.img`
    opacity: 0.8;
  `,

  LoginButton: styled.div`
    display: flex;
    z-index: 1;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 12px;
    position: relative;
    top: 120px;
  `,
};

export default Login;
