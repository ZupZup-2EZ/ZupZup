import styled from 'styled-components';
import { TotalPloggingInfo } from 'types/ProfileInfo';
import { PloggingMemo, TopNavigation } from 'components';
import { URL } from 'utils';

const ploggingInfo: TotalPloggingInfo = {
  totalCalorie: 330, //cal
  totalCount: 1,
  totalTime: 7200, //초
  totalDistance: 1, //미터
  totalGatheredTrash: 20,
};

const trashInfos = [
  { name: '플라스틱', count: 3 },
  { name: '담배꽁초', count: 5 },
  { name: '일반 쓰레기', count: 5 },
  { name: '음식물 쓰레기', count: 5 },
  { name: '유리조각', count: 2 },
];

const MyPloggingReport = () => {
  return (
    <S.Wrap>
      <TopNavigation
        title="누적 레포트"
        rightComponent={<></>}
        navigationTo={URL.MYPAGE.HOME}
      />
      <S.Image src="/assets/character/penguin-stair.png" />
      <S.BoxFrame>
        <div className="title">
          그동안 {ploggingInfo.totalDistance / 1000} km 만큼 플로깅 했어요 👍
        </div>
        <S.BoxInfo>
          <S.EachBoxInfo>
            플로깅 횟수<div className="tag">{ploggingInfo.totalCount}회</div>
          </S.EachBoxInfo>
          <S.EachBoxInfo>
            플로깅 시간
            <div className="tag">
              {Math.floor(ploggingInfo.totalTime / 3600)} 시간
            </div>
          </S.EachBoxInfo>
          <S.EachBoxInfo $isLast={true}>
            소모 칼로리
            <div className="tag">{ploggingInfo.totalCalorie} kcal</div>
          </S.EachBoxInfo>
        </S.BoxInfo>
      </S.BoxFrame>
      <S.BoxFrame>
        <div className="title">플로깅으로 이만큼 개선됐어요!</div>
        <div className="eachInfo">
          총 {ploggingInfo.totalGatheredTrash}회 쓰레기를 주웠어요.
        </div>
        <div className="memoInfo">
          <PloggingMemo trashInfo={trashInfos} />
        </div>
      </S.BoxFrame>

      <S.InfoBox>
        <div className="title">❕ 잠시만요! 그 점 알고 계신가요?</div>
        <div className="content">
          플로깅(plogging) 자세는 스쿼트나 런지 운동 자세와 비슷하여 칼로리
          소모량이 일반 조깅보다 약 50kcal를 더 소모한다는 연구결과가 발표되기도
          했답니다! 일석이조 플로깅, 모두 함께해요 🐧
        </div>
      </S.InfoBox>
    </S.Wrap>
  );
};

interface StyleProps {
  $isLast?: boolean;
}
const S = {
  Wrap: styled.div`
    display: flex;
    width: 100%;
    height: 100dvh;
    overflow-y: scroll;
    flex-direction: column;
    background-color: ${({ theme }) => theme.color.background};
    font-family: ${({ theme }) => theme.font.family.body2};
  `,
  Image: styled.img`
    margin: 20px 0 50px;
    width: 80%;
    align-self: center;
  `,

  BoxFrame: styled.div`
    padding: 0 20px;
    margin-bottom: 50px;
    display: flex;
    flex-direction: column;
    gap: 15px;

    & .title {
      font-family: ${({ theme }) => theme.font.family.display3};
      font-size: ${({ theme }) => theme.font.size.body1};
      font-weight: ${({ theme }) => theme.font.weight.body2};
    }

    & .eachInfo {
      display: flex;
      padding: 0 10px;
      font-size: ${({ theme }) => theme.font.size.focus2};
      font-weight: ${({ theme }) => theme.font.weight.body2};
    }

    & .memoInfo {
      width: 100%;
      display: flex;
      justify-content: center;
    }
  `,

  BoxInfo: styled.div`
    width: 100%;
    height: 95px;
    background-color: ${({ theme }) => theme.color.white};
    border-radius: 4px;
    padding: 14px 0;
    display: flex;
    align-items: center;
    justify-content: center;
  `,

  EachBoxInfo: styled.div<StyleProps>`
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 8px;
    width: calc(80% / 2);
    font-size: ${({ theme }) => theme.font.size.body3};
    font-weight: ${({ theme }) => theme.font.weight.body3};
    border-right: 0.5px solid
      ${({ theme, $isLast }) =>
        $isLast ? theme.color.white : theme.color.gray3};
    & .tag {
      font-family: ${({ theme }) => theme.font.family.focus1};
      font-size: ${({ theme }) => theme.font.size.focus1};
    }
  `,

  InfoBox: styled.div`
    display: flex;
    flex-direction: column;
    padding: 0 20px;
    margin-bottom: 40px;
    font-size: ${({ theme }) => theme.font.size.body3};
    font-family: ${({ theme }) => theme.font.family.body2};

    & .title {
      font-family: ${({ theme }) => theme.font.family.focus2};
      font-size: ${({ theme }) => theme.font.size.body2};
    }

    & .content {
      margin-top: 10px;
      padding: 20px;
      background-color: ${({ theme }) => theme.color.white};
      font-family: ${({ theme }) => theme.font.family.body2};
      line-height: 1.5;
    }
  `,
};

export default MyPloggingReport;
