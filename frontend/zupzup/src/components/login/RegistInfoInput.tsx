import styled from 'styled-components';

import { ChangeEvent, RefObject, useState } from 'react';
import { GENDER } from 'utils';
import SuccessSvg from 'assets/icons/success-check.svg?react';
import ErrorSvg from 'assets/icons/error-check.svg?react';

interface RegistInfoInputProps {
  title: string;
  holderText: string;
  inputRef: RefObject<HTMLInputElement>;
  validCheck: boolean;
  onChange: (e: ChangeEvent<HTMLInputElement>) => void;
  errorMessage: string;
}

interface RegistInfoSelectBoxProps {
  title: string;
  value: string;
  onChange: (value: string) => void;
}

const RegistInfoInput = ({
  title,
  holderText,
  inputRef,
  onChange,
  validCheck,
  errorMessage,
}: RegistInfoInputProps) => {
  return (
    <S.InputBox>
      <S.Title>{title}</S.Title>
      <Input placeholder={holderText} ref={inputRef} onChange={onChange} />
      {validCheck ? (
        <CorrectCheck>
          <SuccessSvg />
          확인되었습니다
        </CorrectCheck>
      ) : (
        <ErrorCheck>
          <ErrorSvg />
          {errorMessage}
        </ErrorCheck>
      )}
    </S.InputBox>
  );
};

const RegistInfoCheckBox = ({
  title,
  value,
  onChange,
}: RegistInfoSelectBoxProps) => {
  const [selectedValue, setSelectedValue] = useState(value);

  const handleRadioChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSelectedValue(e.target.value);
    onChange(e.target.value);
  };
  return (
    <S.InputBox>
      <S.Title>{title}</S.Title>
      <S.CheckBox>
        <label>
          <input
            type="radio"
            value={GENDER.MALE}
            checked={selectedValue === GENDER.MALE}
            onChange={handleRadioChange}
          />
          <span>남성</span>
        </label>
        <label>
          <input
            type="radio"
            value={GENDER.FEMALE}
            checked={selectedValue === GENDER.FEMALE}
            onChange={handleRadioChange}
          />
          <span>여성</span>
        </label>
      </S.CheckBox>
    </S.InputBox>
  );
};

const S = {
  InputBox: styled.div`
    width: 100%;
    padding: 0 18px 30px;
  `,

  CheckBox: styled.div`
    padding: 10px 0 0 10px;
    display: flex;
    flex-direction: column;
    gap: 1rem;
    & label {
      display: flex;
      align-items: center;
      gap: 6px;
    }

    & span {
      margin-left: 0.3rem;
      font-size: ${({ theme }) => theme.font.size.focus2};
      font-family: ${({ theme }) => theme.font.family.body2};
      color: ${({ theme }) => theme.color.dark};
    }

    & input[type='radio'] {
      width: 1.5rem;
      height: 1.5rem;
      aspect-ratio: 1;
      border: calc(1.5rem / 8) solid ${({ theme }) => theme.color.gray3};
      padding: calc(1.5rem / 8);
      background: radial-gradient(
          farthest-side,
          ${({ theme }) => theme.color.main} 94%,
          #0000
        )
        50%/0 0 no-repeat content-box;
      border-radius: 50%;
      outline-offset: calc(1.5rem / 10);
      -webkit-appearance: none;
      -moz-appearance: none;
      appearance: none;
      cursor: pointer;
      font-size: inherit;
      transition: 0.3s;
    }
    & input[type='radio']:checked {
      border-color: ${({ theme }) => theme.color.main};
      background-size: 100% 100%;
    }
  `,

  Title: styled.div`
    font-weight: ${({ theme }) => theme.font.weight.body2};
    font-size: ${({ theme }) => theme.font.size.body2};
    font-family: ${({ theme }) => theme.font.family.focus2};
    color: ${({ theme }) => theme.color.dark};
    margin-bottom: 12px;
  `,
};

const Input = styled.input`
  font-weight: ${({ theme }) => theme.font.weight.body3};
  font-size: ${({ theme }) => theme.font.size.body3};
  font-family: ${({ theme }) => theme.font.family.body2};
  display: flex;
  align-items: center;
  justify-content: center;
  width: 100%;
  height: 56px;
  padding: 12px 16px;
  align-items: center;
  gap: 4px;
  align-self: stretch;
  border: none;
  background-color: ${({ theme }) => theme.color.background};
  color: ${({ theme }) => theme.color.dark};

  &::placeholder {
    font-size: 14px;
    font-weight: 500;
    line-height: 130%;
    letter-spacing: -0.014px;
    color: ${({ theme }) => theme.color.gray3};
  }
  &:focus {
    outline: none;
    border-radius: 0px;
    border-bottom: 1px solid ${({ theme }) => theme.color.main};
  }
`;

const CorrectCheck = styled.div`
  display: flex;
  align-items: center;
  color: ${({ theme }) => theme.color.main};
  gap: 5px;
  font-size: 13px;
  padding: 10px 5px 10px;
  border: none;
  width: fit-content;
  font-family: ${({ theme }) => theme.font.family.body2};
`;
const ErrorCheck = styled.div`
  display: flex;
  align-items: center;
  color: ${({ theme }) => theme.color.warning};
  gap: 5px;
  font-size: 13px;
  padding: 10px 5px 10px;
  border: none;
  width: fit-content;
  font-family: ${({ theme }) => theme.font.family.body2};
`;

export { RegistInfoInput, RegistInfoCheckBox };
