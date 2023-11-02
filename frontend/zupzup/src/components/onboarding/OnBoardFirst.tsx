import styled from 'styled-components';

const OnBoardFirst = () => {
  return (
    <S.Wrap>
      <S.TitleFrame>
        <S.MainTitle>
          안녕하세요,
          <br />
          오늘부터 플로깅을 함께할 로귕입니다{' '}
        </S.MainTitle>
        <S.SubTitle>간단한 줍줍 사용법을 알려드릴게요</S.SubTitle>
      </S.TitleFrame>
      <S.Image src="/assets/character/penguin-hi.png" />
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
    width: 100%;
  `,
};
export default OnBoardFirst;
