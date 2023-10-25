import styled from 'styled-components';
import { useNavigate } from 'react-router-dom';
import * as utils from 'utils';
import { ConfirmButton, RecordReport } from 'components';
import { PloggingReport } from 'types/PloggingReport';
import SaveSvg from 'assets/icons/save.svg?react';
import { useCapture } from 'hooks';

const ploggingReport: PloggingReport = {
  image: '../../../assets/images/route.png',
  record: {
    time: 7814,
    calories: 600,
    distance: 3000,
    coin: 40,
  },
};

const PloggingReport = () => {
  const navigate = useNavigate();
  const { handleCaptureClick, captureRef } = useCapture();

  return (
    <S.Wrap>
      <S.Content ref={captureRef}>
        <S.TitleFrame>
          <S.MainTitle>플로깅 완료</S.MainTitle>
          <S.CloseButton onClick={() => navigate(utils.URL.MYPAGE.HOME)}>
            닫기
          </S.CloseButton>
        </S.TitleFrame>
        <S.SubText>플로깅 기록을 확인해주세요</S.SubText>

        <S.SubTitle>나의 이동 경로</S.SubTitle>
        <S.Image src={ploggingReport.image} />

        <S.SubTitle>기록</S.SubTitle>
        <RecordReport record={ploggingReport.record}></RecordReport>

        <S.SaveImage onClick={handleCaptureClick}>
          <SaveSvg />
          이미지로 저장하기
        </S.SaveImage>
      </S.Content>
      <S.BottomFrame>
        <ConfirmButton
          text="마이페이지로 이동"
          onClick={() => navigate(utils.URL.MYPAGE.HOME)}
        />
      </S.BottomFrame>
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

  Content: styled.div`
    padding: 0 24px;
    overflow-y: scroll;
    &::-webkit-scrollbar {
      display: none;
    }
  `,

  Image: styled.img`
    width: 100%;
    margin-top: 22px;
  `,

  TitleFrame: styled.div`
    margin-top: 25px;
    display: flex;
    justify-content: space-between;
  `,

  CloseButton: styled.div`
    cursor: pointer;
    color: ${({ theme }) => theme.color.main};
    font-size: ${({ theme }) => theme.font.size.focus2};
    font-family: ${({ theme }) => theme.font.family.focus2};
    font-weight: ${({ theme }) => theme.font.weight.body2};
  `,

  MainTitle: styled.div`
    font-size: ${({ theme }) => theme.font.size.display1};
    font-family: ${({ theme }) => theme.font.family.display1};
    font-weight: ${({ theme }) => theme.font.weight.body2};
    line-height: ${({ theme }) => theme.font.lineheight.display1};
  `,

  SubText: styled.div`
    margin-top: 10px;
    color: ${({ theme }) => theme.color.gray2};
    font-size: ${({ theme }) => theme.font.size.body2};
    font-family: ${({ theme }) => theme.font.family.body2};
    font-weight: ${({ theme }) => theme.font.weight.body2};
    line-height: ${({ theme }) => theme.font.lineheight.body2};
  `,

  SubTitle: styled.div`
    margin-top: 35px;
    color: ${({ theme }) => theme.color.gray2};
    font-size: ${({ theme }) => theme.font.size.body1};
    font-family: ${({ theme }) => theme.font.family.focus2};
    font-weight: ${({ theme }) => theme.font.weight.body2};
    line-height: ${({ theme }) => theme.font.lineheight.body2};
  `,

  BottomFrame: styled.div`
    display: flex;
    flex-direction: column;
    align-items: center;
    bottom: 0;
    width: 100%;
    margin: auto 0 25px 0;
  `,

  SaveImage: styled.div`
    cursor: pointer;
    margin: 16px 0;
    display: flex;
    justify-content: flex-end;
    gap: 6px;
    align-items: center;
    font-size: ${({ theme }) => theme.font.size.body3};
    font-family: ${({ theme }) => theme.font.family.focus3};
    font-weight: ${({ theme }) => theme.font.weight.body2};
    color: ${({ theme }) => theme.color.gray2};
  `,
};
export default PloggingReport;
