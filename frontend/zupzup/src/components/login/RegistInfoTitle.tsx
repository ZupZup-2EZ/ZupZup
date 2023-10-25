import styled from 'styled-components';

interface Props {
  mainTitle: string;
  subTitle: string;
}
const RegistInfoTitle = (title: Props) => {
  return (
    <S.Wrap>
      <S.MainTitle>{title.mainTitle}</S.MainTitle>
      <S.SubTitle>{title.subTitle}</S.SubTitle>
    </S.Wrap>
  );
};

const S = {
  Wrap: styled.div`
    margin: 26px 20px 0;
  `,
  MainTitle: styled.div`
    font-size: ${({ theme }) => theme.font.size.display1};
    font-family: ${({ theme }) => theme.font.family.display1};
    font-weight: ${({ theme }) => theme.font.weight.body2};
    line-height: ${({ theme }) => theme.font.lineheight.display1};
  `,
  SubTitle: styled.div`
    margin-top: 10px;
    color: ${({ theme }) => theme.color.gray2};
    font-size: ${({ theme }) => theme.font.size.body2};
    font-family: ${({ theme }) => theme.font.family.body2};
    font-weight: ${({ theme }) => theme.font.weight.body2};
    line-height: ${({ theme }) => theme.font.lineheight.body2};
  `,
};

export default RegistInfoTitle;
