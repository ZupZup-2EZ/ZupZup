import styled from 'styled-components';

interface ButtonAttributes {
  text: string;
  onClick: () => void;
}

const ConfirmButton = ({ text, onClick }: ButtonAttributes) => {
  return <S.Button onClick={onClick}>{text}</S.Button>;
};

const S = {
  Button: styled.div`
    display: flex;
    justify-content: center;
    align-items: center;
    width: calc(100% - 56px);
    height: 52px;
    font-size: ${({ theme }) => theme.font.size.focus2};
    font-family: ${({ theme }) => theme.font.family.focus2};
    line-height: ${({ theme }) => theme.font.lineheight.focus2};
    border-radius: 8px;
    background-color: ${({ theme }) => theme.color.main};
    color: ${({ theme }) => theme.color.white};
    margin: 42px 28px 0;
    padding: 8px 16px;
    pointer-events: auto;

    &:hover {
      cursor: pointer;
      background-color: ${({ theme }) => theme.color.sub};
    }
  `,
};
export default ConfirmButton;
