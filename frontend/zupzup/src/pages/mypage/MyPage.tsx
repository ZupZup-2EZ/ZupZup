import styled from 'styled-components';
import {
  Navigation,
  ProgressBar,
  MyPloggingReport,
  MyPageNav,
} from 'components';
import { ProfileInfo } from 'types/ProfileInfo';

const profileInfo: ProfileInfo = {
  nickname: '줍줍',
  characterImage: 'assets/images/character.png',
  day: 12,
  level: 1,
  exp: 160,
  lastPlogging: {
    count: 2,
    hour: 2,
    calories: 200,
  },
};
const MyPage = () => {
  return (
    <S.Wrap>
      <S.Content>
        <MyPageNav coin={320} />
        <S.Title>
          {profileInfo.nickname}님과 함께한지 <br /> {profileInfo.day} 일째
        </S.Title>
        <S.Level>
          <S.SubInfo>레벨 {profileInfo.level + 1} 까지 </S.SubInfo>
          <ProgressBar score={profileInfo.exp} total={200} />
        </S.Level>
        <S.Report>
          <MyPloggingReport lastPlogging={profileInfo.lastPlogging} />
        </S.Report>
      </S.Content>

      <S.Image src={profileInfo.characterImage}></S.Image>
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
    background: url('assets/images/mypage-wall.png');
  `,
  Title: styled.div`
    font-size: ${({ theme }) => theme.font.size.display1};
    font-family: ${({ theme }) => theme.font.family.title};
    line-height: 29px;
    text-align: right;
    margin-top: 30px;
  `,

  Content: styled.div`
    padding: 0 20px;
  `,

  Image: styled.img`
    position: absolute;
    bottom: 90px;
    margin-left: 30px;
    width: 200px;
  `,

  Level: styled.div`
    display: flex;
    flex-direction: column;
    gap: 5px;
    margin-top: 10px;
  `,
  SubInfo: styled.div`
    font-size: ${({ theme }) => theme.font.size.body3};
    font-family: ${({ theme }) => theme.font.family.body3};
  `,

  Report: styled.div`
    display: flex;
    align-items: center;
    margin-top: 20px;
    justify-content: center;
  `,
};

export default MyPage;
