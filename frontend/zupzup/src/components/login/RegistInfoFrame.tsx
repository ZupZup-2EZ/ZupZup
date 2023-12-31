import styled from 'styled-components';

interface ButtonProps {
  disabled: boolean;
}

const RegistInfoFrame = {
  BottomSection: styled.div`
    display: flex;
    flex-direction: column;
    align-items: center;
    bottom: 0;
    width: 100%;
    margin: auto 0 50px 0;
  `,

  Wrap: styled.div`
    background-color: ${({ theme }) => theme.color.white};
    display: flex;
    flex-direction: column;
    width: 100%;
    height: 100dvh;
  `,

  NextButton: styled.div<ButtonProps>`
    display: flex;
    justify-content: center;
    align-items: center;
    width: 100%;
    height: 52px;
    font-weight: ${({ theme }) => theme.font.weight.body2};
    font-family: ${({ theme }) => theme.font.family.focus2};
    font-size: ${({ theme }) => theme.font.size.focus2};
    color: ${({ disabled, theme }) =>
      disabled ? theme.color.gray3 : theme.color.white};
    background-color: ${({ disabled, theme }) =>
      disabled ? theme.color.gray4 : theme.color.main};
    margin-bottom: 20px;
    cursor: ${({ disabled }) => (disabled ? 'not-allowed' : 'pointer')};
  `,

  InputSection: styled.div`
    display: flex;
    flex-direction: column;
    width: 100%;
    align-items: center;
    justify-content: center;
    margin-top: 60px;
  `,

  info: styled.div`
    margin-top: -10px;
    font-weight: ${({ theme }) => theme.font.weight.body2};
    font-family: ${({ theme }) => theme.font.family.body2};
    font-size: ${({ theme }) => theme.font.size.focus2};
    color: ${({ theme }) => theme.color.main};
  `,
};

export default RegistInfoFrame;
