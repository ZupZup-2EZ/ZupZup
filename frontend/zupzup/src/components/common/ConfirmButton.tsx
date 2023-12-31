import styled from 'styled-components';

interface ButtonAttributes {
  text: string;
  color?: string;
  onClick: () => void;
}

const ConfirmButton = ({ text, color, onClick }: ButtonAttributes) => {
  return (
    <S.Button color={color} onClick={onClick}>
      {text}
    </S.Button>
  );
};

interface StyleProps {
  color?: string;
}

const S = {
  Button: styled.div<StyleProps>`
    display: flex;
    justify-content: center;
    align-items: center;
    width: calc(100% - 56px);
    height: 52px;
    font-size: ${({ theme }) => theme.font.size.focus2};
    font-family: ${({ theme }) => theme.font.family.focus2};
    line-height: ${({ theme }) => theme.font.lineheight.focus2};
    border-radius: 8px;
    background-color: ${({ theme, color }) =>
      color ? color : theme.color.main};
    color: #fff;
    margin: 42px 28px 0;
    padding: 8px 16px;
    pointer-events: auto;

    &:active {
      cursor: pointer;
      background-color: ${({ theme }) => theme.color.sub};
    }
  `,
};
export default ConfirmButton;
