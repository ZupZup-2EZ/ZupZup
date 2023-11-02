import { styled } from 'styled-components';
import { useNavigate } from 'react-router-dom';
import * as utils from 'utils';
import NextArrowSvg from 'assets/icons/angle-right.svg?react';
import { Navigation, TopNavigation } from 'components';
import SettingComponent from 'components/mypage/SettingComponent';

const profileInfo = {
  nickname: '줍줍',
};
const Setting = () => {
  const navigate = useNavigate();

  return (
    <S.Wrap>
      <TopNavigation
        title="설정"
        rightComponent={<></>}
        navigationTo={utils.URL.MYPAGE.HOME}
      />
      <S.SettingSection>
        <S.SubTitle>
          <S.MyInfo onClick={() => navigate(utils.URL.SETTING.PROFILE)}>
            <div className="textInfo">
              <div className="nickname">{profileInfo.nickname} 님</div>
              <div className="modify">내 정보 수정하기</div>
            </div>
            <S.SvgWrapper>
              <NextArrowSvg />
            </S.SvgWrapper>
          </S.MyInfo>
        </S.SubTitle>
      </S.SettingSection>

      <S.SettingSection>
        <S.SubTitle>앱 설정</S.SubTitle>
        <SettingComponent
          text="테마 변경"
          onClick={() => navigate(utils.URL.SETTING.THEME)}
        />
        <SettingComponent
          text="튜토리얼 확인하기"
          onClick={() => navigate(utils.URL.ONBORDING.EXPLAIN)}
        />
      </S.SettingSection>
      <S.SettingSection>
        <S.SubTitle>계정</S.SubTitle>
        <SettingComponent
          text="로그아웃"
          svg={<></>}
          onClick={() => navigate(utils.URL.LOGIN.HOME)}
        />
      </S.SettingSection>

      <S.SettingSection>
        <S.SubTitle>약관</S.SubTitle>
        <SettingComponent
          text="서비스 이용약관"
          onClick={() => navigate(utils.URL.ONBORDING.WORKING)}
        />
        <SettingComponent
          text="개인정보 처리방침"
          onClick={() => navigate(utils.URL.ONBORDING.WORKING)}
        />
        <SettingComponent text="앱 버전" svg={<>1.0.0</>} />
        <SettingComponent
          text="줍줍 새소식"
          onClick={() => navigate(utils.URL.ONBORDING.WORKING)}
        />
        <SettingComponent
          text="오픈소스 라이선스 보기"
          onClick={() => navigate(utils.URL.ONBORDING.WORKING)}
        />
      </S.SettingSection>
      <Navigation />
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
  `,
  SettingSection: styled.div`
    margin-top: 10px;
    margin-left: 24px;
  `,

  SubTitle: styled.div`
    display: flex;
    width: 100%;
    height: 52px;
    align-items: center;
    gap: 10px;
    align-self: stretch;
    font-size: ${({ theme }) => theme.font.size.focus2};
    font-family: ${({ theme }) => theme.font.family.focus2};
  `,

  SvgWrapper: styled.div`
    display: flex;
    padding: 0px 12px;
    justify-content: flex-end;
    align-items: center;
    gap: 2px;
    align-self: stretch;
  `,

  MyInfo: styled.div`
    cursor: pointer;
    display: flex;
    width: 100%;
    justify-content: space-between;
    align-items: center;

    & .textInfo {
      display: flex;
      flex-direction: column;
      gap: 4px;

      & .nickname {
        font-size: ${({ theme }) => theme.font.size.focus2};
        font-family: ${({ theme }) => theme.font.family.focus1};
      }

      & .modify {
        font-size: ${({ theme }) => theme.font.size.caption};
        font-weight: ${({ theme }) => theme.font.weight.caption};
        color: ${({ theme }) => theme.color.gray2};
      }
    }
  `,
};

export default Setting;
