import styled from 'styled-components';

import { ChangeEvent, RefObject, useState } from 'react';
import { GENDER } from 'utils';

interface RegistInfoInputProps {
  title: string;
  holderText: string;
  inputRef: RefObject<HTMLInputElement>;
  onChange: (e: ChangeEvent<HTMLInputElement>) => void;
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
}: RegistInfoInputProps) => {
  return (
    <S.InputBox>
      <S.Title>{title}</S.Title>
      <Input placeholder={holderText} ref={inputRef} onChange={onChange} />
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
    }

    & input[type='radio'] {
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
    margin-bottom: 12px;
  `,
};

const Input = styled.input`
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

export { RegistInfoInput, RegistInfoCheckBox };
