import styled from 'styled-components';

const OnBoardSecond = () => {
  return (
    <S.Wrap>
      <S.TitleFrame>
        <S.MainTitle>
          플로깅을 시작하고 쓰레기를 발견하면
          <br />
          하단의 카메라 버튼을 눌러주세요
        </S.MainTitle>
        <S.SubTitle>
          AI를 통해 인식된 쓰레기 결과에 따라 코인이 부여돼요
        </S.SubTitle>
      </S.TitleFrame>
      <S.Image src="/assets/character/penguin-trash.png" />
    </S.Wrap>
  );
};

const S = {
  Wrap: styled.div`
    display: flex;
    flex-direction: column;
    align-items: center;
    overflow: hidden;
    width: 100%;
    height: 100vh;
    background-color: ${({ theme }) => theme.color.background};
  `,
  TitleFrame: styled.div`
    margin-top: 50px;
    text-align: center;
  `,
  MainTitle: styled.div`
    font-size: ${({ theme }) => theme.font.size.display2};
    font-family: ${({ theme }) => theme.font.family.display2};
    font-weight: ${({ theme }) => theme.font.weight.body2};
    line-height: 1.45;
  `,
  SubTitle: styled.div`
    margin-top: 15px;
    color: ${({ theme }) => theme.color.gray2};
    font-size: ${({ theme }) => theme.font.size.body2};
    font-family: ${({ theme }) => theme.font.family.body2};
    font-weight: ${({ theme }) => theme.font.weight.body2};
    line-height: ${({ theme }) => theme.font.lineheight.body2};
  `,

  Image: styled.img`
    margin: auto;
    width: 95%;
  `,
};
export default OnBoardSecond;
