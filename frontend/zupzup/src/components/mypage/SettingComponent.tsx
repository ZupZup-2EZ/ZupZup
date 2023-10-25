import NextArrowSvg from 'assets/icons/angle-right.svg?react';
import styled from 'styled-components';

interface Props {
  text: string;
  svg?: React.ReactElement;
  onClick?: () => void;
}
const SettingComponent = (props: Props) => {
  return (
    <S.SectionBody>
      <div className="title">{props.text}</div>
      <S.SvgWrapper onClick={() => props.onClick && props.onClick()}>
        {props.svg ? props.svg : <NextArrowSvg />}
      </S.SvgWrapper>
    </S.SectionBody>
  );
};

const S = {
  SectionBody: styled.div`
    cursor: pointer;
    display: flex;
    height: 52px;
    padding: 4px 8px 4px 0px;
    align-items: center;
    gap: 10px;
    align-self: stretch;
    font-size: ${({ theme }) => theme.font.size.focus2};
    font-weight: ${({ theme }) => theme.font.weight.body2};
    line-height: 130%;
    letter-spacing: -0.014px;
    & .title {
      width: 100%;
    }
    & .sub-text {
      font-weight: ${({ theme }) => theme.font.weight.focus2};
      color: ${({ theme }) => theme.color.gray3};
    }
  `,

  SvgWrapper: styled.div`
    display: flex;
    padding: 0px 12px;
    justify-content: flex-end;
    align-items: center;
    gap: 2px;
    align-self: stretch;
  `,
};

export default SettingComponent;
